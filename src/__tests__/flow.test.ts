import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ACCOUNTS, Browser, decodeJwt, pkcePair } from './test-support.js';
import {
  audited,
  authorize,
  authorizePath,
  exchange,
  harness,
  offlineTokens,
  REDIRECT_URI,
  refresh,
  signedInTokens,
  signInAlice,
  startTestServer,
  tokenRequest,
  userinfo,
  WEB_SECRET,
  type Tokens
} from './test-server.js';

let close: () => Promise<void>;
beforeAll(async () => {
  close = await startTestServer();
});
afterAll(() => close());

describe('host sign-in seam', () => {
  it('completes code flow with PKCE and carries the host amr and acr into the ID token', async () => {
    harness.host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(harness.baseUrl));
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get('state')).toBe('xyz');
    const code = redirect.searchParams.get('code');
    expect(code).toBeTruthy();

    const response = await exchange(code!, verifier);
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as {
      id_token: string;
      access_token: string;
      expires_in: number;
    };
    // The shipped oidc-auth-server.ttl.access-token applies when the host sets none.
    expect(tokens.expires_in).toBe(3600);
    const idToken = decodeJwt(tokens.id_token);
    expect(idToken.sub).toBe('alice');
    expect(idToken.amr).toEqual(['pwd', 'otp']);
    expect(idToken.acr).toBe('aal2');
    expect(idToken.auth_time).toBeTypeOf('number');
  });

  it('ends a failed sign-in with access_denied and no code', async () => {
    harness.host = (a, req, res) =>
      a.interactions.fail(req, res, 'access_denied', 'wrong password');
    const { redirect } = await authorize(new Browser(harness.baseUrl));
    expect(redirect.searchParams.get('error')).toBe('access_denied');
    expect(redirect.searchParams.get('code')).toBeNull();
  });

  it('refuses to finish consent while the prompt is still sign-in', async () => {
    harness.host = (a, req, res) => a.interactions.finishConsent(req, res);
    const { url } = await new Browser(harness.baseUrl).follow(
      authorizePath({ code_challenge: pkcePair().challenge, code_challenge_method: 'S256' })
    );
    expect(url).toContain('/interaction/');
  });
});

describe('UserInfo', () => {
  it('returns only the claims the granted scopes name', async () => {
    const { access_token } = await signedInTokens('openid email');
    const response = await userinfo(access_token);
    expect(response.status).toBe(200);
    const claims = (await response.json()) as Record<string, unknown>;
    expect(claims).toMatchObject({
      sub: 'alice',
      email: 'alice@example.com',
      email_verified: true
    });
    expect(claims.name).toBeUndefined();
  });

  it('reports how the person signed in, from the access token', async () => {
    const { access_token } = await signedInTokens('openid');
    const claims = (await (await userinfo(access_token)).json()) as Record<string, unknown>;
    expect(claims).toMatchObject({ sub: 'alice', acr: 'aal2', amr: ['pwd', 'otp'] });
  });

  it('releases profile claims for the profile scope', async () => {
    const { access_token } = await signedInTokens('openid profile');
    const claims = (await (await userinfo(access_token)).json()) as Record<string, unknown>;
    expect(claims.name).toBe('Alice Example');
    expect(claims.email).toBeUndefined();
  });

  it('releases the OIDC Core 5.4 phone and address scopes', async () => {
    const { access_token } = await signedInTokens('openid phone address');
    const claims = (await (await userinfo(access_token)).json()) as Record<string, unknown>;
    expect(claims).toMatchObject({
      phone_number: '+1 555 0100',
      phone_number_verified: true,
      address: { locality: 'Columbus', region: 'OH', country: 'US' }
    });
    expect(claims.email).toBeUndefined();
  });

  it('refuses a revoked access token', async () => {
    const { access_token } = await signedInTokens('openid');
    const revoke = await fetch(`${harness.baseUrl}/token/revocation`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'app', token: access_token })
    });
    expect(revoke.status).toBe(200);
    expect((await userinfo(access_token)).status).toBe(401);
  });

  it('fails closed when the host no longer finds the account', async () => {
    const { access_token } = await signedInTokens('openid email');
    const saved = ACCOUNTS.alice;
    delete ACCOUNTS.alice;
    try {
      expect((await userinfo(access_token)).status).toBe(401);
    } finally {
      ACCOUNTS.alice = saved;
    }
  });
});

describe('refresh token rotation', () => {
  it('issues a new refresh token on every use', async () => {
    const first = await offlineTokens();
    expect(first.refresh_token).toBeTruthy();

    const second = await refresh(first.refresh_token!);
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).toBeTruthy();
    expect(second.body.refresh_token).not.toBe(first.refresh_token);
  });

  it('carries acr and amr through a refresh', async () => {
    const first = await offlineTokens();
    const second = await refresh(first.refresh_token!);
    const claims = (await (await userinfo(second.body.access_token)).json()) as Record<
      string,
      unknown
    >;
    expect(claims).toMatchObject({ acr: 'aal2', amr: ['pwd', 'otp'] });
  });
});

describe('audit', () => {
  const names = (): string[] => audited.map((e) => e.event);

  it('reports a sign-in and token issue, never a token value', async () => {
    audited.length = 0;
    harness.host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(harness.baseUrl));
    const code = redirect.searchParams.get('code')!;
    const tokens = (await (await exchange(code, verifier)).json()) as Tokens & { id_token: string };

    expect(names()).toEqual(expect.arrayContaining(['authorization-allow', 'token-issue']));
    const issue = audited.find((e) => e.event === 'token-issue')!;
    expect(issue).toMatchObject({ clientId: 'app', grantType: 'authorization_code' });
    expect(issue.at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const serialized = JSON.stringify(audited);
    for (const secret of [code, verifier, tokens.access_token, tokens.id_token]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('reports a refused sign-in', async () => {
    audited.length = 0;
    harness.host = (a, req, res) =>
      a.interactions.fail(req, res, 'access_denied', 'wrong password');
    await authorize(new Browser(harness.baseUrl));
    expect(audited.find((e) => e.event === 'authorization-deny')).toMatchObject({
      error: 'access_denied',
      errorDescription: 'wrong password'
    });
  });

  it('reports refresh token reuse as token-reuse and the grant revocation', async () => {
    const first = await offlineTokens();
    await refresh(first.refresh_token!);
    audited.length = 0;
    await refresh(first.refresh_token!);
    expect(names()).toEqual(expect.arrayContaining(['token-reuse', 'grant-revoke']));
    expect(names()).not.toContain('token-error');
  });

  it('reports a revoked token without its value', async () => {
    const { access_token } = await signedInTokens('openid');
    audited.length = 0;
    await tokenRequest({ token: access_token }).catch(() => undefined);
    await fetch(`${harness.baseUrl}/token/revocation`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'app', token: access_token })
    });
    expect(audited.find((e) => e.event === 'token-revoke')).toMatchObject({
      tokenKind: 'AccessToken',
      clientId: 'app',
      accountId: 'alice'
    });
    expect(JSON.stringify(audited)).not.toContain(access_token);
  });
});

describe('confidential clients', () => {
  const basic = (id: string, secret: string): string =>
    `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

  async function codeFor(clientId: string, params: Record<string, string>): Promise<URL> {
    harness.host = signInAlice;
    const { url } = await new Browser(harness.baseUrl).follow(
      authorizePath({ client_id: clientId, ...params })
    );
    return new URL(url);
  }

  it('completes code flow with PKCE and client_secret_basic', async () => {
    const { verifier, challenge } = pkcePair();
    const redirect = await codeFor('web', {
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    const response = await fetch(`${harness.baseUrl}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: basic('web', WEB_SECRET)
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: redirect.searchParams.get('code')!,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier
      })
    });
    expect(response.status).toBe(200);
    expect(decodeJwt(((await response.json()) as { id_token: string }).id_token).sub).toBe('alice');
  });

  it('refuses a wrong secret and never records the secret', async () => {
    const { verifier, challenge } = pkcePair();
    const redirect = await codeFor('web', {
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    audited.length = 0;
    const response = await fetch(`${harness.baseUrl}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: basic('web', 'not-the-secret')
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: redirect.searchParams.get('code')!,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier
      })
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as Tokens).error).toBe('invalid_client');
    const serialized = JSON.stringify(audited);
    expect(serialized).not.toContain('not-the-secret');
    expect(serialized).not.toContain(WEB_SECRET);
  });

  it('still requires PKCE from a confidential client without the exemption', async () => {
    const redirect = await codeFor('web', {});
    expect(redirect.searchParams.get('error')).toBe('invalid_request');
  });

  it('lets an exempt client (require_pkce: false) use code flow without PKCE', async () => {
    const redirect = await codeFor('legacy-web', {});
    const code = redirect.searchParams.get('code');
    expect(code).toBeTruthy();
    const response = await tokenRequest({
      client_id: 'legacy-web',
      client_secret: WEB_SECRET,
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: REDIRECT_URI
    });
    expect(response.status).toBe(200);
  });

  it('still verifies a challenge an exempt client chooses to send', async () => {
    const { challenge } = pkcePair();
    const redirect = await codeFor('legacy-web', {
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    const response = await tokenRequest({
      client_id: 'legacy-web',
      client_secret: WEB_SECRET,
      grant_type: 'authorization_code',
      code: redirect.searchParams.get('code')!,
      redirect_uri: REDIRECT_URI,
      code_verifier: pkcePair().verifier
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as Tokens).error).toBe('invalid_grant');
  });
});
