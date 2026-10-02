import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider, {
  type ClientMetadata,
  type Configuration,
  type KoaContextWithOIDC
} from 'oidc-provider';
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
 * The sign-in's `acr` and `amr`, from whichever grant source the request carries — or, at
 * UserInfo, from the access token they were copied onto. Never from the host's account claims.
 */
function signInOf(ctx: KoaContextWithOIDC): { acr?: string; amr?: string[] } | undefined {
  const { AuthorizationCode, RefreshToken, DeviceCode, AccessToken } = ctx.oidc.entities;
  const source = AuthorizationCode ?? RefreshToken ?? DeviceCode;
  if (source) return { acr: source.acr, amr: source.amr };
  const extra = AccessToken?.extra as { acr?: string; amr?: string[] } | undefined;
  return extra ? { acr: extra.acr, amr: extra.amr } : undefined;
}

/**
 * Build a hardened node-oidc-provider. Unsafe options throw before anything listens.
 *
 * Fixed, not configurable: authorization code flow only, PKCE required for every client
 * (node-oidc-provider accepts S256 only), the provider's development login pages off, and token
 * ids hashed before they reach the host's storage, and refresh tokens rotated on every use.
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
    // How the person signed in rides on the access token, so UserInfo can report it: the host's
    // account lookup knows the person, not the sign-in.
    extraTokenClaims: (ctx, token) => (token.kind === 'AccessToken' ? signInOf(ctx) : undefined),
    findAccount: async (ctx, sub) => {
      const claims = await options.findAccount(sub);
      if (!claims) return undefined;
      return {
        accountId: sub,
        claims: (use) => ({
          ...claims,
          ...(use === 'userinfo' ? signInOf(ctx) : undefined),
          sub
        })
      };
    },
    responseTypes: ['code'],
    // Every refresh issues a new refresh token; presenting a used one revokes the whole grant.
    rotateRefreshToken: true,
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
