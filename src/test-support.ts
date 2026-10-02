// Shared by the test files; excluded from the build.
import { generateKeyPairSync } from 'node:crypto';
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
