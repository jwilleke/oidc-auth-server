// #32: an issuer mounted under a path, as ngdpbase mounts it at <host>/oidc. Every other test
// serves the issuer at the root; this one proves the same flows under /oidc, both behind
// Express's prefix-stripping mount (what ngdpbase uses) and with the full path left on the URL.
import type { IncomingMessage, ServerResponse } from 'node:http';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAuthServer, type AuthServer } from '../create-auth-server.js';
import { createMemoryAdapter } from '../memory-adapter.js';
import type { AuthServerOptions } from '../options.js';
import { baseOptions, Browser, decodeJwt, listen, pkcePair } from './test-support.js';

const MOUNT = '/oidc';
const REDIRECT_URI = 'http://127.0.0.1/cb';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

type Mount = 'express' | 'raw';
type Handler = (req: IncomingMessage, res: ServerResponse) => unknown;

/** The stub host's interaction route: signs alice in, then consents. */
async function signInAlice(
  auth: AuthServer,
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
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
}

function hostRoute(auth: AuthServer): Handler {
  return (req, res) =>
    signInAlice(auth, req, res).catch((error: Error) => {
      res.statusCode = 400;
      res.end(error.message);
    });
}

/**
 * The two ways a host can put the handler under /oidc. Both send /oidc/interaction/* to the host's
 * own route and answer 404 outside /oidc, so a test that reaches the root proves nothing leaks.
 */
function mounted(mount: Mount, auth: AuthServer): Handler {
  const host = hostRoute(auth);
  if (mount === 'express') {
    const app = express();
    // Express strips /oidc from req.url before the handler sees it; the interaction route is
    // passed on to the host, as ngdpbase passes it on to its session-bearing routes.
    app.use(MOUNT, (req, res, next) => {
      if (req.url.startsWith('/interaction/')) next();
      else void auth.handler(req, res);
    });
    app.all(`${MOUNT}/interaction/:uid`, (req, res) => void host(req, res));
    return app;
  }
  return (req, res) => {
    const url = req.url ?? '';
    if (url.startsWith(`${MOUNT}/interaction/`)) return host(req, res);
    if (url === MOUNT || url.startsWith(`${MOUNT}/`) || url.startsWith(`${MOUNT}?`)) {
      return auth.handler(req, res);
    }
    res.statusCode = 404;
    res.end();
    return undefined;
  };
}

function options(issuer: string, overrides: Partial<AuthServerOptions> = {}): AuthServerOptions {
  return baseOptions({
    issuer,
    interactionUrl: (uid) => `${MOUNT}/interaction/${uid}`,
    acrValues: ['aal1', 'aal2'],
    deviceFlow: { enabled: true, throttle: { maxAttempts: 3, windowMinutes: 15 } },
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
        client_id: 'tv',
        token_endpoint_auth_method: 'none',
        grant_types: [DEVICE_GRANT, 'refresh_token'],
        response_types: [],
        redirect_uris: []
      }
    ],
    ...overrides
  });
}

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  device_authorization_endpoint: string;
  [key: string]: unknown;
}

async function form(url: string, params: Record<string, string>): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
}

const xsrfOf = (html: string): string => /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';

describe.each<Mount>(['express', 'raw'])('issuer mounted at /oidc (%s)', (mount) => {
  let server: Awaited<ReturnType<typeof listen>>;
  let issuer: string;
  let discovery: Discovery;
  const setCookies: string[] = [];

  beforeAll(async () => {
    server = await listen((baseUrl) => {
      issuer = `${baseUrl}${MOUNT}`;
      const handler = mounted(mount, createAuthServer(options(issuer)));
      return (req, res) => {
        // Every cookie the server sets, whichever route set it, for the cookie-path test. Read at
        // finish: the cookies library writes through OutgoingMessage.prototype.setHeader directly.
        res.on('finish', () => {
          const value = res.getHeader('set-cookie');
          if (value !== undefined)
            setCookies.push(...([] as string[]).concat(value as string | string[]));
        });
        return handler(req, res);
      };
    });
    const response = await fetch(`${issuer}/.well-known/openid-configuration`);
    expect(response.status).toBe(200);
    discovery = (await response.json()) as Discovery;
  });

  afterAll(() => server.close());

  it('serves discovery under the mount, naming the mounted issuer and mounted endpoints', () => {
    expect(discovery.issuer).toBe(issuer);
    for (const [key, value] of Object.entries(discovery)) {
      if (key.endsWith('_endpoint') || key === 'jwks_uri') {
        expect(value, key).toMatch(new RegExp(`^${issuer}/`));
      }
    }
  });

  it('serves nothing at the root', async () => {
    expect((await fetch(`${server.baseUrl}/.well-known/openid-configuration`)).status).toBe(404);
    expect((await fetch(`${server.baseUrl}/jwks`)).status).toBe(404);
  });

  it('serves the signing keys at the advertised jwks_uri', async () => {
    const response = await fetch(discovery.jwks_uri);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { keys: unknown[] }).keys.length).toBeGreaterThan(0);
  });

  it('completes code flow with PKCE through the host route, and UserInfo answers', async () => {
    const { verifier, challenge } = pkcePair();
    const query = new URLSearchParams({
      client_id: 'app',
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'openid email',
      state: 'xyz',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    const { url } = await new Browser(server.baseUrl).follow(
      `${discovery.authorization_endpoint}?${query.toString()}`
    );
    const redirect = new URL(url);
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
    const code = redirect.searchParams.get('code');
    expect(code, `stopped at ${url}`).toBeTruthy();

    const tokenResponse = await form(discovery.token_endpoint, {
      client_id: 'app',
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier
    });
    expect(tokenResponse.status).toBe(200);
    const tokens = (await tokenResponse.json()) as { id_token: string; access_token: string };
    const idToken = decodeJwt(tokens.id_token);
    expect(idToken.iss).toBe(issuer);
    expect(idToken.acr).toBe('aal2');

    const userinfo = await fetch(discovery.userinfo_endpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}` }
    });
    expect(userinfo.status).toBe(200);
    expect(await userinfo.json()).toMatchObject({
      sub: 'alice',
      email: 'alice@example.com',
      acr: 'aal2'
    });
  });

  it('scopes every cookie it sets to the mount', () => {
    expect(setCookies.length).toBeGreaterThan(0);
    for (const cookie of setCookies) {
      const path = /;\s*path=([^;]*)/i.exec(cookie)?.[1];
      expect(path, cookie).toMatch(new RegExp(`^${MOUNT}(/|$)`));
    }
  });

  it('runs the device flow under the mount', async () => {
    const start = await form(discovery.device_authorization_endpoint, {
      client_id: 'tv',
      scope: 'openid offline_access'
    });
    expect(start.status).toBe(200);
    const device = (await start.json()) as {
      device_code: string;
      user_code: string;
      verification_uri: string;
    };
    expect(device.verification_uri).toBe(`${issuer}/device`);

    const browser = new Browser(server.baseUrl);
    const page = await browser.request(device.verification_uri);
    const entered = await browser.request(device.verification_uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ xsrf: xsrfOf(await page.text()), user_code: device.user_code })
    });
    const confirmHtml = await entered.text();
    const { response } = await browser.follow(device.verification_uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        xsrf: xsrfOf(confirmHtml),
        user_code: device.user_code,
        confirm: 'yes'
      })
    });
    expect(await response.text()).toContain('Device connected');

    const poll = await form(discovery.token_endpoint, {
      grant_type: DEVICE_GRANT,
      device_code: device.device_code,
      client_id: 'tv'
    });
    expect(poll.status).toBe(200);
    expect(((await poll.json()) as { access_token?: string }).access_token).toBeTruthy();
  });

  it('throttles wrong user codes under the mount', async () => {
    const browser = new Browser(server.baseUrl);
    const deviceUrl = `${issuer}/device`;
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const page = await browser.request(deviceUrl);
      const entered = await browser.request(deviceUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ xsrf: xsrfOf(await page.text()), user_code: 'BCDF-GHJK' })
      });
      statuses.push(entered.status);
    }
    expect(statuses.slice(0, 3)).toEqual([200, 200, 200]);
    expect(statuses[3]).toBe(429);
  });
});

describe.each<Mount>(['express', 'raw'])(
  'https issuer at /oidc over a plain-HTTP hop (%s)',
  (mount) => {
    let server: Awaited<ReturnType<typeof listen>>;

    beforeAll(async () => {
      server = await listen(() =>
        mounted(
          mount,
          createAuthServer(
            options('https://auth.example.com/oidc', {
              development: false,
              adapter: createMemoryAdapter(),
              trustProxy: false
            })
          )
        )
      );
    });

    afterAll(() => server.close());

    it('refuses a protocol request, naming the setting', async () => {
      const query = new URLSearchParams({
        client_id: 'app',
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid',
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256'
      });
      const response = await fetch(`${server.baseUrl}${MOUNT}/auth?${query.toString()}`, {
        redirect: 'manual'
      });
      expect(response.status).toBe(400);
      expect(await response.text()).toMatch(/oidc-auth-server\.trust-proxy/);
    });

    it('still serves discovery and JWKS to health probes', async () => {
      const discovery = await fetch(`${server.baseUrl}${MOUNT}/.well-known/openid-configuration`);
      expect(discovery.status).toBe(200);
      expect(((await discovery.json()) as Discovery).issuer).toBe('https://auth.example.com/oidc');
      expect((await fetch(`${server.baseUrl}${MOUNT}/jwks`)).status).toBe(200);
    });
  }
);
