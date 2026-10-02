// Shared by the test files; excluded from the build.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { JWKS } from 'oidc-provider';
import type { AuthServerOptions } from './options.js';

let cachedJwks: JWKS | undefined;

/** One RSA signing key per test run; generating it is the slow part. */
export function testJwks(): JWKS {
  if (!cachedJwks) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    cachedJwks = { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'test', use: 'sig' }] };
  }
  return cachedJwks;
}

export function baseOptions(overrides: Partial<AuthServerOptions> = {}): AuthServerOptions {
  return {
    issuer: 'https://auth.example.com',
    jwks: testJwks(),
    cookieKeys: ['a-cookie-signing-key-of-32-chars!'],
    development: true,
    interactionUrl: (uid) => `/interaction/${uid}`,
    ...overrides
  };
}

type Handler = (req: IncomingMessage, res: ServerResponse) => unknown;

/** Listen on an ephemeral port; returns the base URL and a close function. */
export async function listen(
  build: (baseUrl: string) => Handler
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  let handler: Handler = (_req, res) => res.end();
  const server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  handler = build(baseUrl);
  return {
    baseUrl,
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}

/** A cookie-keeping client that follows redirects by hand and reports where they stopped. */
export class Browser {
  private readonly jar = new Map<string, string>();

  constructor(private readonly baseUrl: string) {}

  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.jar.size > 0) {
      headers.set('cookie', [...this.jar].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    const response = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const line of response.headers.getSetCookie()) {
      const [pair] = line.split(';');
      const index = pair.indexOf('=');
      const name = pair.slice(0, index);
      const value = pair.slice(index + 1);
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(line)) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return response;
  }

  /** Follow redirects until a response is not a redirect or leaves the server. */
  async follow(path: string, init: RequestInit = {}): Promise<{ response: Response; url: string }> {
    let url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    let response = await this.request(url, init);
    for (let hops = 0; hops < 10 && response.status >= 300 && response.status < 400; hops++) {
      url = new URL(response.headers.get('location') ?? '', url).href;
      if (!url.startsWith(this.baseUrl)) break;
      response = await this.request(url);
    }
    return { response, url };
  }
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function decodeJwt(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString()) as Record<
    string,
    unknown
  >;
}
