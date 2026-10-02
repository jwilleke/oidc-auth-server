import { describe, expect, it } from 'vitest';
import { createAuthServer } from './create-auth-server.js';
import { assertSafeOptions } from './options.js';
import { baseOptions, listen, testJwks } from './test-support.js';

describe('assertSafeOptions', () => {
  it('accepts safe options', () => {
    expect(() => assertSafeOptions(baseOptions())).not.toThrow();
  });

  it('refuses an http issuer outside development', () => {
    expect(() =>
      assertSafeOptions(
        baseOptions({
          issuer: 'http://auth.example.com',
          development: false,
          adapter: () => ({}) as never
        })
      )
    ).toThrow(/issuer must use https/);
  });

  it('allows an http issuer in development', () => {
    expect(() => assertSafeOptions(baseOptions({ issuer: 'http://127.0.0.1:9000' }))).not.toThrow();
  });

  it('refuses an issuer with a query or fragment', () => {
    expect(() => assertSafeOptions(baseOptions({ issuer: 'https://a.example.com/?x=1' }))).toThrow(
      /query or fragment/
    );
  });

  it('refuses missing or public-only signing keys', () => {
    expect(() => assertSafeOptions(baseOptions({ jwks: { keys: [] } }))).toThrow(/at least one/);
    const [key] = testJwks().keys;
    const { d: _d, ...publicOnly } = key as Record<string, unknown>;
    expect(() => assertSafeOptions(baseOptions({ jwks: { keys: [publicOnly] } }))).toThrow(
      /private part/
    );
  });

  it('refuses short or missing cookie keys', () => {
    expect(() => assertSafeOptions(baseOptions({ cookieKeys: [] }))).toThrow(/cookieKeys/);
    expect(() => assertSafeOptions(baseOptions({ cookieKeys: ['short'] }))).toThrow(/32/);
  });

  it('refuses to run without a host adapter outside development', () => {
    expect(() => assertSafeOptions(baseOptions({ development: false }))).toThrow(/adapter/);
  });

  it('names every problem in one error', () => {
    expect(() =>
      assertSafeOptions(baseOptions({ issuer: 'nope', cookieKeys: [], jwks: { keys: [] } }))
    ).toThrow(/absolute URL[\s\S]*jwks[\s\S]*cookieKeys/);
  });
});

describe('createAuthServer', () => {
  it('throws before building a provider from unsafe options', () => {
    expect(() => createAuthServer(baseOptions({ cookieKeys: [] }))).toThrow(/refuses to start/);
  });

  it('serves discovery with code flow and S256 PKCE only', async () => {
    const server = await listen(
      (baseUrl) => createAuthServer(baseOptions({ issuer: baseUrl })).handler
    );
    try {
      const response = await fetch(`${server.baseUrl}/.well-known/openid-configuration`);
      expect(response.status).toBe(200);
      const discovery = (await response.json()) as Record<string, unknown>;
      expect(discovery.issuer).toBe(server.baseUrl);
      expect(discovery.response_types_supported).toEqual(['code']);
      expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
    } finally {
      await server.close();
    }
  });
});
