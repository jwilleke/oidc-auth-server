import { describe, expect, it } from 'vitest';
import { AUDIT_EVENT_NAMES } from './audit.js';
import { auditEventsFromConfig, defaultConfig } from './config.js';
import { createAuthServer } from './create-auth-server.js';
import { assertSafeOptions } from './options.js';
import { baseOptions } from './test-support.js';

describe('audit event registry', () => {
  it('declares exactly the events the code reports', () => {
    const declared = Object.keys(
      defaultConfig()['oidc-auth-server.audit.events'] as Record<string, unknown>
    ).sort();
    expect(declared).toEqual([...AUDIT_EVENT_NAMES].sort());
  });

  it('declares every event in {target}-{action} form with a description', () => {
    const events = auditEventsFromConfig(defaultConfig()['oidc-auth-server.audit.events']);
    for (const [name, definition] of Object.entries(events)) {
      expect(name).toMatch(/^[a-z]+-[a-z]+$/);
      expect(definition?.description).toBeTruthy();
      expect(definition?.onFailure).toBe('continue');
    }
  });

  it('refuses an on-failure rule it cannot honour', () => {
    expect(() =>
      assertSafeOptions(
        baseOptions({
          auditEvents: { 'token-issue': { onFailure: 'refuse' as never, description: 'x' } }
        })
      )
    ).toThrow(/cannot be honoured/);
  });

  it('refuses a declared event nothing reports', () => {
    expect(() =>
      assertSafeOptions(
        baseOptions({ auditEvents: { 'page-read': { onFailure: 'continue', description: 'x' } } })
      )
    ).toThrow(/nothing reports it/);
  });
});

describe('audit reporting', () => {
  it('counts a failing callback and never throws into the request', async () => {
    const auth = createAuthServer(
      baseOptions({
        audit: () => Promise.reject(new Error('audit store down'))
      })
    );
    auth.provider.emit('grant.revoked', undefined, 'g1');
    await new Promise((resolve) => setImmediate(resolve));
    expect(auth.auditFailures()).toBe(1);
  });

  it('does not report a disabled or removed event', () => {
    const seen: string[] = [];
    const auth = createAuthServer(
      baseOptions({
        audit: (e) => {
          seen.push(e.event);
        },
        auditEvents: {
          'grant-revoke': { onFailure: 'continue', description: 'x', enabled: false },
          'server-error': null
        }
      })
    );
    auth.provider.emit('grant.revoked', undefined, 'g1');
    auth.provider.emit('server_error', undefined, new Error('boom'));
    expect(seen).toEqual([]);
  });

  it('reports nothing and counts nothing without a callback', () => {
    const auth = createAuthServer(baseOptions());
    auth.provider.emit('grant.revoked', undefined, 'g1');
    expect(auth.auditFailures()).toBe(0);
  });
});
