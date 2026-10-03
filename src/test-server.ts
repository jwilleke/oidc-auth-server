// A booted server with a stub host, shared by the flow and hardening tests; excluded from the
// build. Each test file gets its own module instance, so its own server and state.
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuditEvent } from './audit.js';
import { createAuthServer, type AuthServer } from './create-auth-server.js';
import type { AuthServerOptions } from './options.js';
import { baseOptions, Browser, listen, pkcePair } from './test-support.js';

export const REDIRECT_URI = 'http://127.0.0.1/cb';
export const API = 'https://api.example.com';
export const WEB_SECRET = 'a-confidential-client-secret-for-tests';

export type HostRoute = (
  auth: AuthServer,
  req: IncomingMessage,
  res: ServerResponse
) => Promise<void>;

/** The default stub host: signs everyone in as alice with a password and a TOTP, then consents. */
export const signInAlice: HostRoute = async (auth, req, res) => {
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

/** What the tests steer: the host's interaction route, and where the server listens. */
export const harness: { host: HostRoute; baseUrl: string } = { host: signInAlice, baseUrl: '' };

/** Every audit event the server reported, in order. Tests clear it before what they check. */
export const audited: AuditEvent[] = [];

/** Boot the server; returns its close function for afterAll. */
export async function startTestServer(
  overrides: Partial<AuthServerOptions> = {}
): Promise<() => Promise<void>> {
  const server = await listen((baseUrl) => {
    const auth = createAuthServer(
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
        ],
        ...overrides
      })
    );
    return (req, res) => {
      if (!req.url?.startsWith('/interaction/')) return auth.handler(req, res);
      return harness.host(auth, req, res).catch((error: Error) => {
        res.statusCode = 400;
        res.end(error.message);
      });
    };
  });
  harness.baseUrl = server.baseUrl;
  return server.close;
}

export function authorizePath(params: Record<string, string>): string {
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

export async function authorize(
  browser: Browser,
  params: Record<string, string> = {}
): Promise<{ redirect: URL; verifier: string }> {
  const { verifier, challenge } = pkcePair();
  const { url } = await browser.follow(
    authorizePath({ code_challenge: challenge, code_challenge_method: 'S256', ...params })
  );
  return { redirect: new URL(url), verifier };
}

export async function exchange(code: string, verifier: string): Promise<Response> {
  return tokenRequest({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  });
}

export async function tokenRequest(params: Record<string, string>): Promise<Response> {
  return fetch(`${harness.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: 'app', ...params })
  });
}

export interface Tokens {
  access_token: string;
  refresh_token?: string;
  error?: string;
}

export async function signedInTokens(scope: string): Promise<{ access_token: string }> {
  harness.host = signInAlice;
  const { redirect, verifier } = await authorize(new Browser(harness.baseUrl), { scope });
  const response = await exchange(redirect.searchParams.get('code')!, verifier);
  return (await response.json()) as { access_token: string };
}

export async function offlineTokens(): Promise<Tokens> {
  harness.host = signInAlice;
  const { redirect, verifier } = await authorize(new Browser(harness.baseUrl), {
    scope: 'openid offline_access',
    prompt: 'consent'
  });
  return (await (await exchange(redirect.searchParams.get('code')!, verifier)).json()) as Tokens;
}

export async function refresh(refreshToken: string): Promise<{ status: number; body: Tokens }> {
  const response = await tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken });
  return { status: response.status, body: (await response.json()) as Tokens };
}

export async function userinfo(accessToken: string): Promise<Response> {
  return fetch(`${harness.baseUrl}/me`, { headers: { authorization: `Bearer ${accessToken}` } });
}
