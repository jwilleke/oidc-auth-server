import type { AdapterFactory, ClientMetadata, JWKS } from 'oidc-provider';

/** Lifetimes in seconds. Defaults: `oidc-auth-server.ttl.*` in config/app-default-config.json. */
export interface Ttl {
  accessToken: number;
  authorizationCode: number;
  idToken: number;
  interaction: number;
  session: number;
  grant: number;
  refreshToken: number;
}

/** An API that accepts this server's access tokens. Keyed by resource indicator. */
export interface ResourceServer {
  /** Scopes the API accepts, space-separated. */
  scope: string;
  accessTokenFormat?: 'opaque' | 'jwt';
  /** Seconds; defaults to `ttl.accessToken`. */
  accessTokenTtl?: number;
}

export interface ClientIdMetadataDocumentOptions {
  enabled: boolean;
  /** Hosts whose metadata documents may be fetched. Empty means any public host. */
  allowedHosts?: string[];
}

/**
 * What the host passes to `createAuthServer`. Unset optional settings take the shipped defaults
 * from config/app-default-config.json; `loadConfig` + `optionsFromConfig` build this from files.
 */
export interface AuthServerOptions {
  /** The issuer identifier. HTTPS, no query or fragment. Include the mount path if any. */
  issuer: string;
  /** Private signing keys. At least one, and every key must carry its private part. */
  jwks: JWKS;
  /** Keys that sign the provider's cookies. At least one, each 32 characters or longer. */
  cookieKeys: string[];
  /** Statically registered clients. */
  clients?: ClientMetadata[];
  /**
   * Where the host renders sign-in and consent for a pending interaction. The host's route calls
   * `interactions.finishLogin` / `finishConsent` / `fail` to continue.
   */
  interactionUrl: (uid: string) => string;
  /**
   * The host's account lookup. Returns the person's claims (without `sub`), or undefined when the
   * account no longer exists or is disabled — which fails the request closed. Only the claims the
   * granted scopes name are released.
   */
  findAccount: (accountId: string) => Promise<Record<string, unknown> | undefined>;
  /** Claims released per scope, beyond `openid`. Defaults to OIDC Core 5.4 profile and email. */
  scopeClaims?: Record<string, string[]>;
  /** Token, session and interaction lifetimes; unset entries take the shipped defaults. */
  ttl?: Partial<Ttl>;
  /** APIs that accept access tokens; a token for one names it as audience. Unknown ones are refused. */
  resourceServers?: Record<string, ResourceServer>;
  /** Client ID Metadata Documents. Off unless enabled. */
  clientIdMetadataDocument?: ClientIdMetadataDocumentOptions;
  /** The `acr` values the host's sign-in can produce, advertised in discovery. */
  acrValues?: string[];
  /** Host storage. Required outside development; see `createMemoryAdapter` for tests. */
  adapter?: AdapterFactory;
  /**
   * Allows an `http:` issuer and the in-memory adapter. Never set this in production.
   * Defaults to false.
   */
  development?: boolean;
}

const MIN_COOKIE_KEY_LENGTH = 32;

/**
 * Refuse to build a server from unsafe options. Throws one error naming every problem, so a
 * misconfigured host fails at boot rather than at the first request.
 */
export function assertSafeOptions(options: AuthServerOptions): void {
  const problems: string[] = [];
  const development = options.development === true;

  let issuer: URL | undefined;
  try {
    issuer = new URL(options.issuer);
  } catch {
    problems.push('issuer must be an absolute URL');
  }
  if (issuer) {
    if (issuer.protocol !== 'https:' && !(development && issuer.protocol === 'http:')) {
      problems.push('issuer must use https (http is allowed only with development: true)');
    }
    if (issuer.search || issuer.hash) {
      problems.push('issuer must not carry a query or fragment');
    }
  }

  const keys = options.jwks?.keys ?? [];
  if (keys.length === 0) {
    problems.push('jwks must hold at least one signing key');
  } else if (keys.some((key) => !('d' in key) || !key.d)) {
    problems.push('every jwks key must include its private part');
  }

  const cookieKeys = options.cookieKeys ?? [];
  if (cookieKeys.length === 0) {
    problems.push('cookieKeys must hold at least one key');
  } else if (cookieKeys.some((key) => key.length < MIN_COOKIE_KEY_LENGTH)) {
    problems.push(`every cookieKeys entry must be at least ${MIN_COOKIE_KEY_LENGTH} characters`);
  }

  if (typeof options.interactionUrl !== 'function') {
    problems.push('interactionUrl must be a function');
  }

  if (typeof options.findAccount !== 'function') {
    problems.push('findAccount must be a function');
  }

  for (const [indicator, server] of Object.entries(options.resourceServers ?? {})) {
    let url: URL | undefined;
    try {
      url = new URL(indicator);
    } catch {
      problems.push(`resource server ${indicator} must be an absolute URL`);
    }
    if (url?.hash) problems.push(`resource server ${indicator} must not carry a fragment`);
    if (typeof server.scope !== 'string' || server.scope.trim() === '') {
      problems.push(`resource server ${indicator} must declare the scopes it accepts`);
    }
    if (server.accessTokenFormat && !['opaque', 'jwt'].includes(server.accessTokenFormat)) {
      problems.push(`resource server ${indicator} access-token-format must be opaque or jwt`);
    }
  }

  if (!options.adapter && !development) {
    problems.push('adapter is required outside development');
  }

  if (problems.length > 0) {
    throw new Error(`oidc-auth-server refuses to start:\n- ${problems.join('\n- ')}`);
  }
}
