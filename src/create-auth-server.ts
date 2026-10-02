import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider, { type Configuration } from 'oidc-provider';
import { hashingAdapter } from './hashing-adapter.js';
import { interactionHelpers, type InteractionHelpers } from './interactions.js';
import { createMemoryAdapter } from './memory-adapter.js';
import { assertSafeOptions, type AuthServerOptions } from './options.js';

/** OIDC Core 5.4: the claims the profile and email scopes request. */
const STANDARD_SCOPE_CLAIMS: Record<string, string[]> = {
  profile: [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at'
  ],
  email: ['email', 'email_verified']
};

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

  const configuration: Configuration = {
    adapter: hashingAdapter(options.adapter ?? createMemoryAdapter()),
    clients: options.clients ?? [],
    jwks: options.jwks,
    cookies: { keys: options.cookieKeys },
    interactions: { url: (_ctx, interaction) => options.interactionUrl(interaction.uid) },
    acrValues: options.acrValues ?? [],
    // Standalone claims are issued only when a client asks for them. How the person signed in is
    // the point of the sign-in seam, so it rides on the openid scope every ID token carries.
    claims: {
      sid: null,
      iss: null,
      openid: ['sub', 'acr', 'amr', 'auth_time'],
      ...(options.scopeClaims ?? STANDARD_SCOPE_CLAIMS)
    },
    findAccount: async (_ctx, sub) => {
      const claims = await options.findAccount(sub);
      if (!claims) return undefined;
      return { accountId: sub, claims: () => ({ ...claims, sub }) };
    },
    responseTypes: ['code'],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true }
    }
  };

  const provider = new Provider(options.issuer, configuration);
  return { provider, handler: provider.callback(), interactions: interactionHelpers(provider) };
}
