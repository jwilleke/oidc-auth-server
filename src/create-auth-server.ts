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
import {
  assertSafeOptions,
  isConfidential,
  type AuthServerOptions,
  type SignInContext
} from './options.js';

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
 * How the person signed in — `acr`, `amr` and when (`authTime`, epoch seconds) — from whichever
 * grant source the request carries, from the access token they were copied onto (UserInfo), or
 * from the provider session (the authorization request). Never from the host's account claims.
 */
function signInOf(ctx: KoaContextWithOIDC): SignInContext | undefined {
  const { AuthorizationCode, RefreshToken, DeviceCode, AccessToken } = ctx.oidc.entities;
  const source = AuthorizationCode ?? RefreshToken ?? DeviceCode;
  if (source) return { acr: source.acr, amr: source.amr, authTime: source.authTime };
  const extra = AccessToken?.extra as
    | { acr?: string; amr?: string[]; auth_time?: number }
    | undefined;
  if (extra) return { acr: extra.acr, amr: extra.amr, authTime: extra.auth_time };
  const session = ctx.oidc.session;
  if (session?.accountId) {
    return { acr: session.acr, amr: session.amr, authTime: session.authTime() };
  }
  return undefined;
}

/** What UserInfo reports about the sign-in: `acr` and `amr`, never the host's other context. */
function reportedSignIn(
  signIn: SignInContext | undefined
): { acr?: string; amr?: string[] } | undefined {
  return signIn ? { acr: signIn.acr, amr: signIn.amr } : undefined;
}

/** The issuer's path without a trailing slash: '' for an issuer at the root, '/oidc' at <host>/oidc. */
function mountPathOf(issuer: string): string {
  return new URL(issuer).pathname.replace(/\/+$/, '');
}

/**
 * node-oidc-provider routes only on the path below its mount: a router that strips the prefix
 * (Express `app.use('/oidc', handler)`) gives it that. A host that passes the full path, such as
 * a plain `http` server, would get a 404 for every endpoint, so the prefix is removed here when the
 * request still carries it. A request already stripped never starts with it, unless its own path
 * repeats the mount — and no endpoint does. `originalUrl` keeps the full path, as Express sets it:
 * the provider builds every URL it advertises from the difference between the two.
 */
function underMount(
  mount: string,
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  if (!mount) return handler;
  return (req, res) => {
    const url = req.url ?? '/';
    if (url === mount || url.startsWith(`${mount}/`) || url.startsWith(`${mount}?`)) {
      (req as IncomingMessage & { originalUrl?: string }).originalUrl ??= url;
      req.url = url.slice(mount.length) || '/';
      if (req.url.startsWith('?')) req.url = `/${req.url}`;
    }
    return handler(req, res);
  };
}

/**
 * node-oidc-provider builds every URL it advertises — discovery's endpoints, the device
 * verification URI, redirects to the interaction page — from the request's Host (or, behind a
 * trusted proxy, X-Forwarded-Host). A forged header would then make discovery point clients at
 * someone else's endpoints, and a shared cache would keep serving it. The issuer is configured, so
 * its host is the only one this server answers as: the request's is replaced before the provider
 * reads it.
 */
function atIssuerHost(
  issuer: string,
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const host = new URL(issuer).host;
  return (req, res) => {
    req.headers.host = host;
    delete req.headers['x-forwarded-host'];
    return handler(req, res);
  };
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
    // Scoped to the issuer's path, so an issuer mounted at <host>/oidc never sends its session
    // cookie with the host's own requests. The interaction cookies set a narrower path themselves.
    cookies: {
      keys: options.cookieKeys,
      long: { httpOnly: true, sameSite: 'lax', path: mountPathOf(options.issuer) || '/' },
      short: { httpOnly: true, sameSite: 'lax', path: mountPathOf(options.issuer) || '/' }
    },
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
    // auth_time rides along too, so the host's account lookup can refuse a sign-in older than,
    // say, the account's last password change.
    extraTokenClaims: (ctx, token) => {
      if (token.kind !== 'AccessToken') return undefined;
      const signIn = signInOf(ctx);
      return signIn ? { acr: signIn.acr, amr: signIn.amr, auth_time: signIn.authTime } : undefined;
    },
    findAccount: async (ctx, sub) => {
      const signIn = signInOf(ctx);
      const claims = await options.findAccount(sub, signIn);
      if (!claims) return undefined;
      return {
        accountId: sub,
        claims: (use) => ({
          ...claims,
          ...(use === 'userinfo' ? reportedSignIn(signIn) : undefined),
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
    handler: atIssuerHost(
      options.issuer,
      underMount(mountPathOf(options.issuer), provider.callback())
    ),
    interactions: interactionHelpers(provider),
    auditFailures: audit.failures
  };
}
