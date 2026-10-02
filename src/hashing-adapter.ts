import { createHash } from 'node:crypto';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';

/**
 * Models whose id is itself a bearer credential. Their id is stored as a SHA-256 hash, so a
 * read of the host's storage yields nothing that can be presented to the server.
 */
export const HASHED_MODELS: ReadonlySet<string> = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'ClientCredentials',
  'BackchannelAuthenticationRequest',
  'RegistrationAccessToken',
  'InitialAccessToken',
  'PreAuthorizedCode'
]);

/**
 * Marks an id that is already a hash. A lookup by uid or user code (the device flow) returns a
 * stored row whose plaintext id is unknown; the provider may save that row again, and the marker
 * keeps it from being hashed twice. Generated token ids never contain a colon.
 */
const HASHED_PREFIX = 'sha256:';

/** Hash a presented token value. Never honours the marker: a stored hash is not a credential. */
export function hashTokenId(id: string): string {
  return createHash('sha256').update(id).digest('base64url');
}

/** The storage key for an id the provider itself holds, which may already be a marked hash. */
function storageKey(id: string): string {
  return id.startsWith(HASHED_PREFIX) ? id.slice(HASHED_PREFIX.length) : hashTokenId(id);
}

/**
 * Wrap the host's adapter so token ids — and the `jti` that repeats them inside the payload — are
 * hashed before they reach storage. The plaintext id is restored on the way back out, from the
 * value the caller presented. Other models pass through untouched.
 */
export function hashingAdapter(inner: AdapterFactory): AdapterFactory {
  return (name: string): Adapter => {
    const adapter = inner(name);
    if (!HASHED_MODELS.has(name)) return adapter;

    const restore = (
      stored: AdapterPayload | undefined | void,
      id: string
    ): AdapterPayload | undefined => (stored ? { ...stored, jti: id } : undefined);
    const marked = (stored: AdapterPayload | undefined | void): AdapterPayload | undefined =>
      stored ? { ...stored, jti: `${HASHED_PREFIX}${stored.jti}` } : undefined;

    return {
      upsert: (id, payload, expiresIn) => {
        const hashed = storageKey(id);
        return adapter.upsert(hashed, { ...payload, jti: hashed }, expiresIn);
      },
      find: async (id) => restore(await adapter.find(hashTokenId(id)), id),
      findByUid: async (uid) => marked(await adapter.findByUid(uid)),
      findByUserCode: async (userCode) => marked(await adapter.findByUserCode(userCode)),
      consume: (id) => adapter.consume(storageKey(id)),
      destroy: (id) => adapter.destroy(storageKey(id)),
      revokeByGrantId: (grantId) => adapter.revokeByGrantId(grantId)
    };
  };
}
