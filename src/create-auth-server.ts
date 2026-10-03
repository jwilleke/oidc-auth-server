import type { IncomingMessage, ServerResponse } from 'node:http';
import Provider, {
  errors,
  type ClientMetadata,
  type Configuration,
  type KoaContextWithOIDC
} from 'oidc-provider';
import { attachAudit } from './audit.js';
import {
  applyPollingInterval,
  applyUserCodeThrottle,
  deviceFlowFeature,
  userCodeThrottle,
  type DeviceFlowOptions
} from './device-flow.js';
import { auditEventsFromConfig, defaultConfig, ttlFromConfig } from './config.js';
import { hashingAdapter } from './hashing-adapter.js';
import { interactionHelpers, type InteractionHelpers } from './interactions.js';
import { createMemoryAdapter } from './memory-adapter.js';
import { allowMetadataFetch, guardedFetch } from './outgoing-fetch.js';
import { assertSafeOptions, isConfidential, type AuthServerOptions } from './options.js';

export interface AuthServer {
  /** The underlying node-oidc-provider instance. */
  provider: Provider;
  /** Mount this under the issuer's path in Express, Koa or a plain `http` server. */
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  /** Called from the host's interaction route to finish or fail sign-in and consent. */
  interactions: InteractionHelpers;
  /** Audit reports the host's callback failed to take. Zero when no callback is set. */
  auditFailures: () => number;
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

/** Paths a health probe may fetch over plain HTTP: they set no cookie and carry no secret. */
const PROBE_PATHS = /\/(\.well-known\/openid-configuration|jwks)$/;

/**
 * With an https issuer, refuse a request that is not secure as Koa sees it — direct TLS, or a
 * trusted proxy's X-Forwarded-Proto. Otherwise cookies go out without Secure and the client IP
 * is the proxy's. The usual cause is a TLS-terminating proxy without trust-proxy set.
 */
function refusePlainHttp(provider: Provider): void {
  provider.use(async (ctx, next) => {
    if (ctx.secure || (ctx.method === 'GET' && PROBE_PATHS.test(ctx.path))) {
      await next();
      return;
    }
    ctx.status = 400;
    ctx.type = 'text';
    ctx.body =
      'This https issuer was reached over plain HTTP. Behind a TLS-terminating proxy, set oidc-auth-server.trust-proxy and forward X-Forwarded-Proto.';
  });
}

/**
 * Build a hardened node-oidc-provider. Unsafe options throw before anything listens.
 *
 * Fixed, not configurable: authorization code flow only, PKCE required for every client
 * (node-oidc-provider accepts S256 only) unless a confidential client sets require_pkce: false, the provider's development login pages off, and token
 * ids hashed before they reach the host's storage, and refresh tokens rotated on every use.
 */
export function createAuthServer(options: AuthServerOptions): AuthServer {
  assertSafeOptions(options);
  const defaults = defaultConfig();
  const ttl = { ...ttlFromConfig(defaults), ...options.ttl };

  const resourceServers = options.resourceServers ?? {};
  const metadataDocuments = options.clientIdMetadataDocument ?? {
    enabled: defaults['oidc-auth-server.client-id-metadata-document.enabled'] as boolean,
    allowedHosts: defaults['oidc-auth-server.client-id-metadata-document.allowed-hosts'] as string[]
  };

  const deviceFlow: DeviceFlowOptions = options.deviceFlow ?? {
    enabled: defaults['oidc-auth-server.device-flow.enabled'] as boolean
  };
  const throttle = userCodeThrottle(
    deviceFlow.throttle?.maxAttempts ??
      (defaults['oidc-auth-server.device-flow.throttle.max-attempts'] as number),
    deviceFlow.throttle?.windowMinutes ??
      (defaults['oidc-auth-server.device-flow.throttle.window-minutes'] as number)
  );

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
      RefreshToken: ttl.refreshToken,
      DeviceCode: ttl.deviceCode
    },
    // PKCE for every client, unless a confidential client opts out with require_pkce: false
    // (operator, 2026-10-03). A challenge an exempt client does send is still verified.
    pkce: { required: (_ctx, client) => client.metadata().require_pkce !== false },
    extraClientMetadata: {
      properties: ['require_pkce'],
      validator: (_ctx, key, value, metadata) => {
        if (key !== 'require_pkce' || value === undefined) return;
        if (typeof value !== 'boolean') {
          throw new errors.InvalidClientMetadata('require_pkce must be a boolean');
        }
        if (value === false && !isConfidential(metadata)) {
          throw new errors.InvalidClientMetadata(
            'require_pkce: false is allowed only for a confidential client'
          );
        }
      }
    },
    fetch: guardedFetch(),
    features: {
      devInteractions: { enabled: false },
      // Not configured means not loaded: with the feature off the provider mounts no device routes.
      deviceFlow: deviceFlow.enabled ? deviceFlowFeature(deviceFlow, throttle) : { enabled: false },
      clientIdMetadataDocument: {
        enabled: metadataDocuments.enabled,
        ack: 'draft-02',
        allowFetch: (_ctx, clientId) => allowMetadataFetch(clientId, metadataDocuments.allowedHosts)
      },
      // A token for an API names it as audience (RFC 8707); an unlisted resource is refused.
      resourceIndicators: {
        enabled: true,
        defaultResource: (_ctx, _client, oneOf) => oneOf,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, indicator) => {
          const server = resourceServers[indicator];
          if (!server) throw new errors.InvalidTarget();
          return {
            scope: server.scope,
            audience: indicator,
            accessTokenFormat: server.accessTokenFormat ?? 'opaque',
            accessTokenTTL: server.accessTokenTtl ?? ttl.accessToken
          };
        }
      },
      revocation: { enabled: true }
    }
  };

  const provider = new Provider(options.issuer, configuration);
  provider.proxy = options.trustProxy ?? (defaults['oidc-auth-server.trust-proxy'] as boolean);
  if (new URL(options.issuer).protocol === 'https:') refusePlainHttp(provider);
  if (deviceFlow.enabled) {
    applyUserCodeThrottle(provider, throttle);
    applyPollingInterval(provider, ttl.deviceCode);
  }
  const registry =
    options.auditEvents ?? auditEventsFromConfig(defaults['oidc-auth-server.audit.events']);
  let audit = { failures: (): number => 0 };
  if (options.audit) audit = attachAudit(provider, options.audit, registry);
  return {
    provider,
    handler: provider.callback(),
    interactions: interactionHelpers(provider),
    auditFailures: audit.failures
  };
}
