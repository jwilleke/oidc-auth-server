// The hardening checklist from activescott/auth#83, the package's review list (AGENTS.md, Key
// Decisions), each item proved end to end against one booted server. A regression in any item
// shows here, in one place. Functional behaviour lives in flow.test.ts.
import type { AdapterFactory } from 'oidc-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createMemoryAdapter } from '../memory-adapter.js';
import { Browser, decodeJwt, pkcePair } from './test-support.js';
import {
  API,
  audited,
  authorize,
  authorizePath,
  exchange,
  harness,
  offlineTokens,
  REDIRECT_URI,
  refresh,
  signInAlice,
  startTestServer,
  tokenRequest,
  userinfo,
  type Tokens
} from './test-server.js';

/** Everything written to storage — key and payload — for the hashed-at-rest check. */
const stored: string[] = [];
const recordingAdapter: AdapterFactory = (() => {
  const inner = createMemoryAdapter();
  return (name) => {
    const adapter = inner(name);
    return {
      ...adapter,
      upsert: (id, payload, expiresIn) => {
        stored.push(`${name} ${id} ${JSON.stringify(payload)}`);
        return adapter.upsert(id, payload, expiresIn);
      }
    };
  };
})();

let close: () => Promise<void>;
beforeAll(async () => {
  close = await startTestServer({ adapter: recordingAdapter });
});
afterAll(() => close());

describe('1. authorization code reuse revokes the tokens it issued', () => {
  it('refuses a second exchange and revokes the tokens the first one issued', async () => {
    harness.host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(harness.baseUrl));
    const code = redirect.searchParams.get('code')!;

    const first = (await (await exchange(code, verifier)).json()) as Tokens;
    expect(first.access_token).toBeTruthy();

    audited.length = 0;
    const second = await exchange(code, verifier);
    expect(second.status).toBe(400);
    expect(audited.map((e) => e.event)).toContain('token-reuse');
    expect(((await second.json()) as Tokens).error).toBe('invalid_grant');
    expect((await userinfo(first.access_token)).status).toBe(401);
  });
});

describe('2. PKCE required, S256 only', () => {
  it('advertises S256 and nothing else', async () => {
    const discovery = (await (
      await fetch(`${harness.baseUrl}/.well-known/openid-configuration`)
    ).json()) as Record<string, unknown>;
    expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('refuses an authorization request without PKCE', async () => {
    harness.host = signInAlice;
    const { url } = await new Browser(harness.baseUrl).follow(authorizePath({}));
    const redirect = new URL(url);
    expect(redirect.searchParams.get('error')).toBe('invalid_request');
    expect(redirect.searchParams.get('code')).toBeNull();
  });

  it('refuses the plain PKCE method', async () => {
    harness.host = signInAlice;
    const { url } = await new Browser(harness.baseUrl).follow(
      authorizePath({ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' })
    );
    expect(new URL(url).searchParams.get('code')).toBeNull();
    expect(new URL(url).searchParams.get('error')).toBe('invalid_request');
  });

  it('refuses a code exchanged with the wrong verifier', async () => {
    harness.host = signInAlice;
    const { redirect } = await authorize(new Browser(harness.baseUrl));
    const response = await exchange(redirect.searchParams.get('code')!, pkcePair().verifier);
    expect(response.status).toBe(400);
    expect(((await response.json()) as Tokens).error).toBe('invalid_grant');
  });
});

describe('3. audience on every token an API accepts', () => {
  it('names the resource server as the audience of its access token', async () => {
    harness.host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(harness.baseUrl), {
      scope: 'openid api:read',
      resource: API
    });
    const response = await tokenRequest({
      grant_type: 'authorization_code',
      code: redirect.searchParams.get('code')!,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: API
    });
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as Tokens & { scope: string };
    const accessToken = decodeJwt(tokens.access_token);
    expect(accessToken.aud).toBe(API);
    expect(accessToken.scope).toBe('api:read');
    expect(accessToken).toMatchObject({ acr: 'aal2', amr: ['pwd', 'otp'] });
  });

  it('refuses a resource that is not a registered resource server', async () => {
    harness.host = signInAlice;
    const { redirect } = await authorize(new Browser(harness.baseUrl), {
      resource: 'https://other.example.com'
    });
    expect(redirect.searchParams.get('error')).toBe('invalid_target');
    expect(redirect.searchParams.get('code')).toBeNull();
  });
});

describe('4. refresh token reuse detection', () => {
  it('revokes the whole grant when a used refresh token is presented again', async () => {
    const first = await offlineTokens();
    const second = await refresh(first.refresh_token!);
    expect(second.status).toBe(200);

    const replay = await refresh(first.refresh_token!);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    // The thief's replay also cuts off the legitimate holder: every token of the grant is gone.
    expect((await refresh(second.body.refresh_token!)).status).toBe(400);
    expect((await userinfo(second.body.access_token)).status).toBe(401);
    expect((await userinfo(first.access_token)).status).toBe(401);
  });
});

describe('5. single-use consent', () => {
  it('accepts a consent only once', async () => {
    const consentUrls: string[] = [];
    harness.host = async (a, req, res) => {
      const pending = await a.interactions.details(req, res);
      if (pending.prompt === 'consent') consentUrls.push(req.url ?? '');
      return signInAlice(a, req, res);
    };
    const browser = new Browser(harness.baseUrl);
    const { redirect } = await authorize(browser);
    expect(redirect.searchParams.get('code')).toBeTruthy();
    expect(consentUrls).toHaveLength(1);

    const replay = await browser.request(consentUrls[0]);
    expect(replay.status).toBe(400);
  });
});

describe('6. tokens hashed at rest', () => {
  it('writes no issued code or token to storage, as key or inside a row', async () => {
    stored.length = 0;
    harness.host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(harness.baseUrl), {
      scope: 'openid offline_access',
      prompt: 'consent'
    });
    const code = redirect.searchParams.get('code')!;
    const first = (await (await exchange(code, verifier)).json()) as Tokens;
    const second = await refresh(first.refresh_token!);
    await tokenRequest({ token: second.body.access_token }).catch(() => undefined);
    await fetch(`${harness.baseUrl}/token/revocation`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'app', token: second.body.refresh_token! })
    });

    const secrets = [
      code,
      first.access_token,
      first.refresh_token!,
      second.body.access_token,
      second.body.refresh_token!
    ];
    expect(secrets.every(Boolean)).toBe(true);
    const tokenRows = stored.filter((row) =>
      /^(AccessToken|AuthorizationCode|RefreshToken) /.test(row)
    );
    expect(tokenRows.length).toBeGreaterThanOrEqual(5);
    const everything = stored.join('\n');
    for (const secret of secrets) expect(everything).not.toContain(secret);
  });
});

describe('7. SSRF-guarded client ID metadata documents', () => {
  it.each(['https://127.0.0.1/client.json', 'https://169.254.169.254/latest/meta-data'])(
    'refuses %s as a client without fetching it',
    async (clientId) => {
      const { challenge } = pkcePair();
      const query = new URLSearchParams({
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid',
        code_challenge: challenge,
        code_challenge_method: 'S256'
      });
      const response = await new Browser(harness.baseUrl).request(`/auth?${query.toString()}`);
      expect(response.status).toBe(400);
      expect(await response.text()).toMatch(/metadata document fetch not allowed/);
    }
  );
});
