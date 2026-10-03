import { describe, expect, it } from 'vitest';
import type { AdapterFactory, AdapterPayload } from 'oidc-provider';
import { hashTokenId, hashingAdapter } from './hashing-adapter.js';
import { createMemoryAdapter } from './memory-adapter.js';

/** A memory adapter that also exposes every key and payload written to it. */
function spyAdapter(): { factory: AdapterFactory; writes: Array<[string, AdapterPayload]> } {
  const inner = createMemoryAdapter();
  const writes: Array<[string, AdapterPayload]> = [];
  const factory: AdapterFactory = (name) => {
    const adapter = inner(name);
    return {
      ...adapter,
      upsert: (id, payload, expiresIn) => {
        writes.push([id, payload]);
        return adapter.upsert(id, payload, expiresIn);
      }
    };
  };
  return { factory, writes };
}

const TOKEN = 'plaintext-token-value';

describe('hashingAdapter', () => {
  it('never writes a token id in plaintext, as key or inside the payload', async () => {
    const { factory, writes } = spyAdapter();
    const accessTokens = hashingAdapter(factory)('AccessToken');
    await accessTokens.upsert(TOKEN, { jti: TOKEN, kind: 'AccessToken', grantId: 'g1' }, 60);

    expect(writes).toHaveLength(1);
    const [key, payload] = writes[0];
    expect(key).toBe(hashTokenId(TOKEN));
    expect(JSON.stringify(payload)).not.toContain(TOKEN);
  });

  it('finds by the presented value and returns the plaintext jti', async () => {
    const accessTokens = hashingAdapter(createMemoryAdapter())('AccessToken');
    await accessTokens.upsert(TOKEN, { jti: TOKEN, kind: 'AccessToken' }, 60);

    const found = await accessTokens.find(TOKEN);
    expect(found?.jti).toBe(TOKEN);
  });

  it('does not accept the stored hash as a credential', async () => {
    const accessTokens = hashingAdapter(createMemoryAdapter())('AccessToken');
    await accessTokens.upsert(TOKEN, { jti: TOKEN, kind: 'AccessToken' }, 60);

    expect(await accessTokens.find(hashTokenId(TOKEN))).toBeUndefined();
  });

  it('consumes and destroys through the hash', async () => {
    const codes = hashingAdapter(createMemoryAdapter())('AuthorizationCode');
    await codes.upsert(TOKEN, { jti: TOKEN, kind: 'AuthorizationCode' }, 60);

    await codes.consume(TOKEN);
    expect((await codes.find(TOKEN))?.consumed).toBeTypeOf('number');

    await codes.destroy(TOKEN);
    expect(await codes.find(TOKEN)).toBeUndefined();
  });

  it('refuses a lookup by user code or uid on a hashed model', async () => {
    const accessTokens = hashingAdapter(createMemoryAdapter())('AccessToken');
    await expect(accessTokens.findByUserCode('ABCD')).rejects.toThrow(/cannot be found/);
    await expect(accessTokens.findByUid('uid')).rejects.toThrow(/cannot be found/);
  });

  it('passes device codes through: the interaction row must find them again', async () => {
    const { factory, writes } = spyAdapter();
    await hashingAdapter(factory)('DeviceCode').upsert('dc', { jti: 'dc', userCode: 'ABCD' }, 60);
    expect(writes[0][0]).toBe('dc');
  });

  it('revokes every token of a grant', async () => {
    const adapter = hashingAdapter(createMemoryAdapter());
    const accessTokens = adapter('AccessToken');
    const refreshTokens = adapter('RefreshToken');
    await accessTokens.upsert('at', { jti: 'at', grantId: 'g1' }, 60);
    await refreshTokens.upsert('rt', { jti: 'rt', grantId: 'g1' }, 60);

    await accessTokens.revokeByGrantId('g1');
    expect(await accessTokens.find('at')).toBeUndefined();
    expect(await refreshTokens.find('rt')).toBeUndefined();
  });

  it('passes models that are not credentials through unchanged', async () => {
    const { factory, writes } = spyAdapter();
    await hashingAdapter(factory)('Session').upsert('session-id', { jti: 'session-id' }, 60);
    expect(writes[0][0]).toBe('session-id');
  });
});
