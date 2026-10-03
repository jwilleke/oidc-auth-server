import { createHash } from 'node:crypto';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';

/**
 * Models whose id is itself a bearer credential. Their id is stored as a SHA-256 hash, so a
 * read of the host's storage yields nothing that can be presented to the server.
 *
 * Not here, deliberately: DeviceCode, Session and Interaction. The provider keeps a device code's
 * id inside the interaction row and finds the code again by it, so any reference stored for that
 * purpose is itself presentable — hashing would protect nothing. Each lives minutes, not days.
 */
export const HASHED_MODELS: ReadonlySet<string> = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'ClientCredentials',
  'BackchannelAuthenticationRequest',
  'RegistrationAccessToken',
  'InitialAccessToken',
  'PreAuthorizedCode'
]);

/** Hash a token value. A stored hash presented as a token hashes again and finds nothing. */
export function hashTokenId(id: string): string {
  return createHash('sha256').update(id).digest('base64url');
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

    return {
      upsert: (id, payload, expiresIn) => {
        const hashed = hashTokenId(id);
        return adapter.upsert(hashed, { ...payload, jti: hashed }, expiresIn);
      },
      find: async (id) => restore(await adapter.find(hashTokenId(id)), id),
      // A hashed model's row found any other way would come back without its plaintext id, and a
      // later save would land under a new key. None is looked up that way; refuse if one ever is.
      findByUid: () => Promise.reject(new Error(`${name} is hashed and cannot be found by uid`)),
      findByUserCode: () =>
        Promise.reject(new Error(`${name} is hashed and cannot be found by user code`)),
      consume: (id) => adapter.consume(hashTokenId(id)),
      destroy: (id) => adapter.destroy(hashTokenId(id)),
      revokeByGrantId: (grantId) => adapter.revokeByGrantId(grantId)
    };
  };
}
