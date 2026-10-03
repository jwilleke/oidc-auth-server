import type { IncomingMessage, ServerResponse } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuditEvent } from './audit.js';
import { createAuthServer, type AuthServer } from './create-auth-server.js';
import { ACCOUNTS, baseOptions, Browser, decodeJwt, listen, pkcePair } from './test-support.js';

const REDIRECT_URI = 'http://127.0.0.1/cb';
const API = 'https://api.example.com';
const WEB_SECRET = 'a-confidential-client-secret-for-tests';

type HostRoute = (auth: AuthServer, req: IncomingMessage, res: ServerResponse) => Promise<void>;

/** The default stub host: signs everyone in as alice with a password and a TOTP, then consents. */
const signInAlice: HostRoute = async (auth, req, res) => {
  const pending = await auth.interactions.details(req, res);
  if (pending.prompt === 'login') {
    await auth.interactions.finishLogin(req, res, {
      accountId: 'alice',
      amr: ['pwd', 'otp'],
      acr: 'aal2'
    });
  } else {
    await auth.interactions.finishConsent(req, res);
  }
};

let auth: AuthServer;
const audited: AuditEvent[] = [];
let host: HostRoute = signInAlice;
let server: Awaited<ReturnType<typeof listen>>;
const consentUrls: string[] = [];

beforeAll(async () => {
  server = await listen((baseUrl) => {
    auth = createAuthServer(
      baseOptions({
        issuer: baseUrl,
        acrValues: ['aal1', 'aal2'],
        resourceServers: {
          [API]: { scope: 'api:read', accessTokenFormat: 'jwt' }
        },
        clientIdMetadataDocument: { enabled: true, allowedHosts: [] },
        audit: (event) => {
          audited.push(event);
        },
        clients: [
          {
            client_id: 'app',
            application_type: 'native',
            token_endpoint_auth_method: 'none',
            redirect_uris: [REDIRECT_URI],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code']
          },
          {
            client_id: 'web',
            client_secret: WEB_SECRET,
            application_type: 'native',
            token_endpoint_auth_method: 'client_secret_basic',
            redirect_uris: [REDIRECT_URI],
            grant_types: ['authorization_code'],
            response_types: ['code']
          },
          {
            client_id: 'legacy-web',
            client_secret: WEB_SECRET,
            application_type: 'native',
            token_endpoint_auth_method: 'client_secret_post',
            require_pkce: false,
            redirect_uris: [REDIRECT_URI],
            grant_types: ['authorization_code'],
            response_types: ['code']
          }
        ]
      })
    );
    return (req, res) => {
      if (!req.url?.startsWith('/interaction/')) return auth.handler(req, res);
      return host(auth, req, res).catch((error: Error) => {
        res.statusCode = 400;
        res.end(error.message);
      });
    };
  });
});

afterAll(() => server.close());

function authorizePath(params: Record<string, string>): string {
  const query = new URLSearchParams({
    client_id: 'app',
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid',
    state: 'xyz',
    ...params
  });
  return `/auth?${query.toString()}`;
}

async function authorize(
  browser: Browser,
  params: Record<string, string> = {}
): Promise<{ redirect: URL; verifier: string }> {
  const { verifier, challenge } = pkcePair();
  const { url } = await browser.follow(
    authorizePath({ code_challenge: challenge, code_challenge_method: 'S256', ...params })
  );
  return { redirect: new URL(url), verifier };
}

async function exchange(code: string, verifier: string): Promise<Response> {
  return fetch(`${server.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'app',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier
    })
  });
}

describe('host sign-in seam', () => {
  it('completes code flow with PKCE and carries the host amr and acr into the ID token', async () => {
    host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(server.baseUrl));
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

  it('refuses an authorization request without PKCE', async () => {
    host = signInAlice;
    const { url } = await new Browser(server.baseUrl).follow(authorizePath({}));
    const redirect = new URL(url);
    expect(redirect.searchParams.get('error')).toBe('invalid_request');
    expect(redirect.searchParams.get('code')).toBeNull();
  });

  it('refuses the plain PKCE method', async () => {
    host = signInAlice;
    const { url } = await new Browser(server.baseUrl).follow(
      authorizePath({ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' })
    );
    expect(new URL(url).searchParams.get('code')).toBeNull();
    expect(new URL(url).searchParams.get('error')).toBe('invalid_request');
  });

  it('ends a failed sign-in with access_denied and no code', async () => {
    host = (a, req, res) => a.interactions.fail(req, res, 'access_denied', 'wrong password');
    const { redirect } = await authorize(new Browser(server.baseUrl));
    expect(redirect.searchParams.get('error')).toBe('access_denied');
    expect(redirect.searchParams.get('code')).toBeNull();
  });

  it('accepts a consent only once', async () => {
    consentUrls.length = 0;
    host = async (a, req, res) => {
      const pending = await a.interactions.details(req, res);
      if (pending.prompt === 'consent') consentUrls.push(req.url ?? '');
      return signInAlice(a, req, res);
    };
    const browser = new Browser(server.baseUrl);
    const { redirect } = await authorize(browser);
    expect(redirect.searchParams.get('code')).toBeTruthy();
    expect(consentUrls).toHaveLength(1);

    const replay = await browser.request(consentUrls[0]);
    expect(replay.status).toBe(400);
  });

  it('refuses to finish consent while the prompt is still sign-in', async () => {
    host = (a, req, res) => a.interactions.finishConsent(req, res);
    const { url } = await new Browser(server.baseUrl).follow(
      authorizePath({ code_challenge: pkcePair().challenge, code_challenge_method: 'S256' })
    );
    expect(url).toContain('/interaction/');
  });
});

async function signedInTokens(scope: string): Promise<{ access_token: string }> {
  host = signInAlice;
  const { redirect, verifier } = await authorize(new Browser(server.baseUrl), { scope });
  const response = await exchange(redirect.searchParams.get('code')!, verifier);
  return (await response.json()) as { access_token: string };
}

async function userinfo(accessToken: string): Promise<Response> {
  return fetch(`${server.baseUrl}/me`, { headers: { authorization: `Bearer ${accessToken}` } });
}

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
    const revoke = await fetch(`${server.baseUrl}/token/revocation`, {
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

async function tokenRequest(params: Record<string, string>): Promise<Response> {
  return fetch(`${server.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: 'app', ...params })
  });
}

interface Tokens {
  access_token: string;
  refresh_token?: string;
  error?: string;
}

async function offlineTokens(): Promise<Tokens> {
  host = signInAlice;
  const { redirect, verifier } = await authorize(new Browser(server.baseUrl), {
    scope: 'openid offline_access',
    prompt: 'consent'
  });
  return (await (await exchange(redirect.searchParams.get('code')!, verifier)).json()) as Tokens;
}

async function refresh(refreshToken: string): Promise<{ status: number; body: Tokens }> {
  const response = await tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken });
  return { status: response.status, body: (await response.json()) as Tokens };
}

describe('refresh token rotation', () => {
  it('issues a new refresh token on every use', async () => {
    const first = await offlineTokens();
    expect(first.refresh_token).toBeTruthy();

    const second = await refresh(first.refresh_token!);
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).toBeTruthy();
    expect(second.body.refresh_token).not.toBe(first.refresh_token);
  });

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

describe('authorization code reuse', () => {
  it('refuses a second exchange and revokes the tokens the first one issued', async () => {
    host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(server.baseUrl));
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

describe('audience', () => {
  it('names the resource server as the audience of its access token', async () => {
    host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(server.baseUrl), {
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
    host = signInAlice;
    const { redirect } = await authorize(new Browser(server.baseUrl), {
      resource: 'https://other.example.com'
    });
    expect(redirect.searchParams.get('error')).toBe('invalid_target');
    expect(redirect.searchParams.get('code')).toBeNull();
  });
});

describe('client ID metadata documents', () => {
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
      const response = await new Browser(server.baseUrl).request(`/auth?${query.toString()}`);
      expect(response.status).toBe(400);
      expect(await response.text()).toMatch(/metadata document fetch not allowed/);
    }
  );
});

describe('audit', () => {
  const names = (): string[] => audited.map((e) => e.event);

  it('reports a sign-in and token issue, never a token value', async () => {
    audited.length = 0;
    host = signInAlice;
    const { redirect, verifier } = await authorize(new Browser(server.baseUrl));
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
    host = (a, req, res) => a.interactions.fail(req, res, 'access_denied', 'wrong password');
    await authorize(new Browser(server.baseUrl));
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
    await fetch(`${server.baseUrl}/token/revocation`, {
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
    host = signInAlice;
    const { url } = await new Browser(server.baseUrl).follow(
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
    const response = await fetch(`${server.baseUrl}/token`, {
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
    const response = await fetch(`${server.baseUrl}/token`, {
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
