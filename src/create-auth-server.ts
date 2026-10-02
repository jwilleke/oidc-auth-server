import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider, { type Configuration } from 'oidc-provider';
import { hashingAdapter } from './hashing-adapter.js';
import { createMemoryAdapter } from './memory-adapter.js';
import { assertSafeOptions, type AuthServerOptions } from './options.js';

export interface AuthServer {
  /** The underlying node-oidc-provider instance. */
  provider: Provider;
  /** Mount this under the issuer's path in Express, Koa or a plain `http` server. */
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}

/**
 * Build a hardened node-oidc-provider. Unsafe options throw before anything listens.
 *
 * Fixed, not configurable: authorization code flow only, PKCE required for every client
 * (node-oidc-provider accepts S256 only), the provider's development login pages off, and token
 * ids hashed before they reach the host's storage.
 */
export function createAuthServer(options: AuthServerOptions): AuthServer {
  assertSafeOptions(options);

  const configuration: Configuration = {
    adapter: hashingAdapter(options.adapter ?? createMemoryAdapter()),
    clients: options.clients ?? [],
    jwks: options.jwks,
    cookies: { keys: options.cookieKeys },
    responseTypes: ['code'],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true }
    }
  };

  const provider = new Provider(options.issuer, configuration);
  return { provider, handler: provider.callback() };
}
