import type { IncomingMessage, ServerResponse } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAuthServer, type AuthServer } from './create-auth-server.js';
import { baseOptions, Browser, decodeJwt, listen, pkcePair } from './test-support.js';

const REDIRECT_URI = 'http://127.0.0.1/cb';

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
let host: HostRoute = signInAlice;
let server: Awaited<ReturnType<typeof listen>>;
const consentUrls: string[] = [];

beforeAll(async () => {
  server = await listen((baseUrl) => {
    auth = createAuthServer(
      baseOptions({
        issuer: baseUrl,
        acrValues: ['aal1', 'aal2'],
        clients: [
          {
            client_id: 'app',
            application_type: 'native',
            token_endpoint_auth_method: 'none',
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
    const tokens = (await response.json()) as { id_token: string; access_token: string };
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
