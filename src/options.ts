import type { AdapterFactory, ClientMetadata, JWKS } from 'oidc-provider';

/** What the host passes to `createAuthServer`. */
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

  if (!options.adapter && !development) {
    problems.push('adapter is required outside development');
  }

  if (problems.length > 0) {
    throw new Error(`oidc-auth-server refuses to start:\n- ${problems.join('\n- ')}`);
  }
}
