import { describe, expect, it } from 'vitest';
import type { AuditEvent } from '../audit.js';
import { createAuthServer } from '../create-auth-server.js';
import { createMemoryAdapter } from '../memory-adapter.js';
import { baseOptions, listen, pkcePair } from './test-support.js';

// An https issuer served over a plain-HTTP hop: what every TLS-terminating proxy, Docker port
// mapping behind nginx and Kubernetes ingress looks like from the process.
const ISSUER = 'https://auth.example.com';

async function serve(trustProxy: boolean, audited: AuditEvent[] = []): ReturnType<typeof listen> {
  return listen(
    () =>
      createAuthServer(
        baseOptions({
          issuer: ISSUER,
          development: false,
          adapter: createMemoryAdapter(),
          trustProxy,
          audit: (event) => {
            audited.push(event);
          },
          clients: [
            {
              client_id: 'app',
              application_type: 'native',
              token_endpoint_auth_method: 'none',
              redirect_uris: ['http://127.0.0.1/cb']
            }
          ]
        })
      ).handler
  );
}

const authorizeQuery = (): string =>
  new URLSearchParams({
    client_id: 'app',
    redirect_uri: 'http://127.0.0.1/cb',
    response_type: 'code',
    scope: 'openid',
    code_challenge: pkcePair().challenge,
    code_challenge_method: 'S256'
  }).toString();

describe('https issuer behind a TLS-terminating proxy', () => {
  it('refuses plain HTTP when the proxy is not trusted, naming the setting', async () => {
    const server = await serve(false);
    try {
      const response = await fetch(`${server.baseUrl}/auth?${authorizeQuery()}`, {
        redirect: 'manual',
        headers: { 'x-forwarded-proto': 'https' }
      });
      expect(response.status).toBe(400);
      expect(await response.text()).toMatch(/oidc-auth-server\.trust-proxy/);
    } finally {
      await server.close();
    }
  });

  it('serves discovery and JWKS over plain HTTP for health probes', async () => {
    const server = await serve(false);
    try {
      expect((await fetch(`${server.baseUrl}/.well-known/openid-configuration`)).status).toBe(200);
      expect((await fetch(`${server.baseUrl}/jwks`)).status).toBe(200);
    } finally {
      await server.close();
    }
  });

  it('with trust-proxy, sets Secure cookies and sees the client IP the proxy forwarded', async () => {
    const audited: AuditEvent[] = [];
    const server = await serve(true, audited);
    try {
      const response = await fetch(`${server.baseUrl}/auth?${authorizeQuery()}`, {
        redirect: 'manual',
        headers: { 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.7' }
      });
      expect(response.status).toBe(303);
      const cookies = response.headers.getSetCookie();
      expect(cookies.length).toBeGreaterThan(0);
      expect(cookies.every((cookie) => /;\s*secure/i.test(cookie))).toBe(true);

      await fetch(`${server.baseUrl}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'x-forwarded-proto': 'https',
          'x-forwarded-for': '203.0.113.7'
        },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'app', code: 'x' })
      });
      expect(audited.find((e) => e.event === 'oidctoken-error')?.ip).toBe('203.0.113.7');
    } finally {
      await server.close();
    }
  });

  it('with trust-proxy, still refuses a request the proxy did not mark https', async () => {
    const server = await serve(true);
    try {
      const response = await fetch(`${server.baseUrl}/auth?${authorizeQuery()}`, {
        redirect: 'manual'
      });
      expect(response.status).toBe(400);
    } finally {
      await server.close();
    }
  });

  it('advertises the issuer host, whatever Host or X-Forwarded-Host the request carries', async () => {
    for (const trustProxy of [false, true]) {
      const server = await serve(trustProxy);
      try {
        const response = await fetch(`${server.baseUrl}/.well-known/openid-configuration`, {
          headers: {
            host: 'evil.example',
            'x-forwarded-host': 'evil.example',
            'x-forwarded-proto': 'https'
          }
        });
        expect(response.status).toBe(200);
        const discovery = (await response.json()) as Record<string, unknown>;
        for (const [key, value] of Object.entries(discovery)) {
          if (key.endsWith('_endpoint') || key === 'jwks_uri') {
            const url = new URL(value as string);
            expect(url.host, `${key} with trustProxy ${String(trustProxy)}`).toBe(
              'auth.example.com'
            );
            // Untrusted, the hop is plain HTTP and Koa reports it as such: only health probes are
            // answered there. Trusted, the proxy's https is believed.
            if (trustProxy) expect(url.protocol, key).toBe('https:');
          }
        }
      } finally {
        await server.close();
      }
    }
  });
});
