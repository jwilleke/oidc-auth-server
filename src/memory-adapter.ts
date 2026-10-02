import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';

interface Entry {
  payload: AdapterPayload;
  expiresAt: number;
}

/**
 * An in-process adapter for development and tests. State is lost on restart and is not shared
 * between processes, so `createAuthServer` refuses it outside development.
 */
export function createMemoryAdapter(): AdapterFactory {
  const models = new Map<string, Map<string, Entry>>();

  const live = (store: Map<string, Entry>, id: string): Entry | undefined => {
    const entry = store.get(id);
    if (entry && entry.expiresAt <= Date.now()) {
      store.delete(id);
      return undefined;
    }
    return entry;
  };

  const findBy = (
    store: Map<string, Entry>,
    field: 'uid' | 'userCode',
    value: string
  ): AdapterPayload | undefined => {
    for (const [id, entry] of store) {
      if (entry.payload[field] === value) {
        return live(store, id) ? { ...entry.payload } : undefined;
      }
    }
    return undefined;
  };

  const all = (): Array<[Map<string, Entry>, string, Entry]> => {
    const rows: Array<[Map<string, Entry>, string, Entry]> = [];
    for (const store of models.values()) {
      for (const [id, entry] of store) rows.push([store, id, entry]);
    }
    return rows;
  };

  return (name: string): Adapter => {
    let store = models.get(name);
    if (!store) {
      store = new Map();
      models.set(name, store);
    }
    const own = store;

    return {
      upsert(id, payload, expiresIn) {
        const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : Infinity;
        own.set(id, { payload: { ...payload }, expiresAt });
        return Promise.resolve();
      },
      find(id) {
        const entry = live(own, id);
        return Promise.resolve(entry ? { ...entry.payload } : undefined);
      },
      findByUid(uid) {
        return Promise.resolve(findBy(own, 'uid', uid));
      },
      findByUserCode(userCode) {
        return Promise.resolve(findBy(own, 'userCode', userCode));
      },
      consume(id) {
        const entry = live(own, id);
        if (entry) entry.payload.consumed = Math.floor(Date.now() / 1000);
        return Promise.resolve();
      },
      destroy(id) {
        own.delete(id);
        return Promise.resolve();
      },
      revokeByGrantId(grantId) {
        for (const [owner, id, entry] of all()) {
          if (entry.payload.grantId === grantId) owner.delete(id);
        }
        return Promise.resolve();
      }
    };
  };
}
