import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { defaultConfig, loadConfig, optionsFromConfig } from './config.js';
import { assertSafeOptions } from './options.js';
import { testJwks } from './test-support.js';

// Only this test's own temporary directory is ever removed.
const scratch = mkdtempSync(join(tmpdir(), 'oidc-auth-server-config-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const COOKIE_KEY = 'a-cookie-signing-key-of-32-chars!';
const env = {
  OIDC_AUTH_SERVER_JWKS: JSON.stringify(testJwks()),
  OIDC_AUTH_SERVER_COOKIE_KEYS: `${COOKIE_KEY}, ${COOKIE_KEY}-2`
};
const callbacks = {
  interactionUrl: (uid: string) => `/interaction/${uid}`,
  findAccount: () => Promise.resolve(undefined)
};

describe('defaultConfig', () => {
  it('holds no comments and no secrets', () => {
    const config = defaultConfig();
    expect(Object.keys(config).some((key) => key.startsWith('_comment'))).toBe(false);
    expect(config['oidc-auth-server.jwks']).toBeUndefined();
    expect(config['oidc-auth-server.cookie-keys']).toBeUndefined();
  });

  it('refuses to boot on its own: the issuer and secrets must be supplied', () => {
    expect(() => assertSafeOptions(optionsFromConfig(defaultConfig(), callbacks))).toThrow(
      /issuer[\s\S]*jwks[\s\S]*cookieKeys/
    );
  });
});

describe('loadConfig', () => {
  it('layers a custom file over the defaults, merging maps per entry', () => {
    const path = join(scratch, 'app-custom-config.json');
    writeFileSync(
      path,
      JSON.stringify({
        _comment: 'ignored',
        'oidc-auth-server.issuer': 'https://auth.example.com',
        'oidc-auth-server.ttl.access-token': 300,
        'oidc-auth-server.scope-claims': { phone: ['phone_number'] },
        'unrelated.key': true
      })
    );
    const config = loadConfig({ customConfigPath: path, env: {} });
    expect(config['oidc-auth-server.issuer']).toBe('https://auth.example.com');
    expect(config['oidc-auth-server.ttl.access-token']).toBe(300);
    const scopeClaims = config['oidc-auth-server.scope-claims'] as Record<string, string[]>;
    expect(scopeClaims.phone).toEqual(['phone_number']);
    expect(scopeClaims.email).toEqual(['email', 'email_verified']);
    expect(config['unrelated.key']).toBeUndefined();
  });

  it('treats a missing custom file as no overrides', () => {
    expect(() =>
      loadConfig({ customConfigPath: join(scratch, 'absent.json'), env: {} })
    ).not.toThrow();
  });

  it('refuses an unknown key rather than ignoring a typo', () => {
    expect(() =>
      loadConfig({ customConfig: { 'oidc-auth-server.ttl.acess-token': 1 }, env: {} })
    ).toThrow(/ttl.acess-token is not a known setting/);
  });

  it('refuses a secret written into a file', () => {
    expect(() =>
      loadConfig({ customConfig: { 'oidc-auth-server.cookie-keys': COOKIE_KEY }, env: {} })
    ).toThrow(/owned by the environment \(OIDC_AUTH_SERVER_COOKIE_KEYS\)/);
  });

  it('reads secrets from the environment into safe options', () => {
    const config = loadConfig({
      customConfig: { 'oidc-auth-server.issuer': 'https://auth.example.com' },
      env
    });
    const options = optionsFromConfig(config, { ...callbacks, adapter: () => ({}) as never });
    expect(options.cookieKeys).toEqual([COOKIE_KEY, `${COOKIE_KEY}-2`]);
    expect(options.jwks.keys).toHaveLength(1);
    expect(options.ttl?.accessToken).toBe(3600);
    expect(() => assertSafeOptions(options)).not.toThrow();
  });

  it('refuses a jwks variable that is not JSON', () => {
    const config = loadConfig({ env: { OIDC_AUTH_SERVER_JWKS: '{nope' } });
    expect(() => optionsFromConfig(config, callbacks)).toThrow(/jwks is not valid JSON/);
  });
});
