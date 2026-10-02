import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider, { type ClientMetadata, type Configuration } from 'oidc-provider';
import { defaultConfig, ttlFromConfig } from './config.js';
import { hashingAdapter } from './hashing-adapter.js';
import { interactionHelpers, type InteractionHelpers } from './interactions.js';
import { createMemoryAdapter } from './memory-adapter.js';
import { assertSafeOptions, type AuthServerOptions } from './options.js';

export interface AuthServer {
  /** The underlying node-oidc-provider instance. */
  provider: Provider;
  /** Mount this under the issuer's path in Express, Koa or a plain `http` server. */
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  /** Called from the host's interaction route to finish or fail sign-in and consent. */
  interactions: InteractionHelpers;
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
  const defaults = defaultConfig();
  const ttl = { ...ttlFromConfig(defaults), ...options.ttl };

  const configuration: Configuration = {
    adapter: hashingAdapter(options.adapter ?? createMemoryAdapter()),
    clients: options.clients ?? (defaults['oidc-auth-server.clients'] as ClientMetadata[]),
    jwks: options.jwks,
    cookies: { keys: options.cookieKeys },
    interactions: { url: (_ctx, interaction) => options.interactionUrl(interaction.uid) },
    acrValues: options.acrValues ?? (defaults['oidc-auth-server.acr-values'] as string[]),
    // Standalone claims are issued only when a client asks for them. How the person signed in is
    // the point of the sign-in seam, so it rides on the openid scope every ID token carries.
    claims: {
      sid: null,
      iss: null,
      openid: ['sub', 'acr', 'amr', 'auth_time'],
      ...(options.scopeClaims ??
        (defaults['oidc-auth-server.scope-claims'] as Record<string, string[]>))
    },
    findAccount: async (_ctx, sub) => {
      const claims = await options.findAccount(sub);
      if (!claims) return undefined;
      return { accountId: sub, claims: () => ({ ...claims, sub }) };
    },
    responseTypes: ['code'],
    ttl: {
      AccessToken: ttl.accessToken,
      AuthorizationCode: ttl.authorizationCode,
      IdToken: ttl.idToken,
      Interaction: ttl.interaction,
      Session: ttl.session,
      Grant: ttl.grant,
      RefreshToken: ttl.refreshToken
    },
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true }
    }
  };

  const provider = new Provider(options.issuer, configuration);
  return { provider, handler: provider.callback(), interactions: interactionHelpers(provider) };
}
