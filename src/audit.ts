import type Provider from 'oidc-provider';
import type { KoaContextWithOIDC } from 'oidc-provider';

/**
 * Every event the code reports, once. `oidc-auth-server.audit.events` in
 * config/app-default-config.json declares the same names; a test holds the two equal.
 */
export const AUDIT_EVENT_NAMES = [
  'authorization-allow',
  'authorization-deny',
  'token-issue',
  'token-error',
  'token-reuse',
  'token-revoke',
  'grant-revoke',
  'userinfo-error',
  'server-error'
] as const;

export type AuditEventName = (typeof AUDIT_EVENT_NAMES)[number];

/** One registry entry, as `oidc-auth-server.audit.events` declares it. */
export interface AuditEventDefinition {
  onFailure: 'continue';
  description: string;
  enabled?: boolean;
}

/** What the host's audit callback receives. Never a token, code or secret. */
export interface AuditEvent {
  event: AuditEventName;
  /** ISO 8601. */
  at: string;
  clientId?: string;
  accountId?: string;
  grantId?: string;
  grantType?: string;
  scope?: string;
  /** The token kind, for token-revoke. */
  tokenKind?: string;
  error?: string;
  errorDescription?: string;
  /** The server-side reason, which the client is not told. */
  errorDetail?: string;
  ip?: string;
  userAgent?: string;
}

export type AuditSink = (event: AuditEvent) => void | Promise<void>;

interface OAuthError {
  error?: string;
  error_description?: string;
  error_detail?: string;
}

interface TokenLike {
  kind: string;
  clientId?: string;
  accountId?: string;
  grantId?: string;
}

const REUSE = /already (used|consumed)/;

/**
 * Report node-oidc-provider's events to the host as registry-named audit events. Returns a
 * counter of reports the host's callback failed to take: the action has already happened by
 * the time an event fires, so a failure can only be counted, never used to refuse.
 */
export function attachAudit(
  provider: Provider,
  sink: AuditSink,
  registry: Record<string, AuditEventDefinition | null>
): { failures: () => number } {
  let failures = 0;

  const report = (
    event: AuditEventName,
    ctx: KoaContextWithOIDC | undefined,
    fields: Partial<AuditEvent>
  ): void => {
    const definition = registry[event];
    if (!definition || definition.enabled === false) return;
    const record: AuditEvent = {
      event,
      at: new Date().toISOString(),
      clientId: ctx?.oidc?.client?.clientId,
      accountId: ctx?.oidc?.session?.accountId ?? ctx?.oidc?.account?.accountId,
      ip: ctx?.ip,
      userAgent: ctx?.get?.('user-agent') || undefined,
      ...fields
    };
    for (const key of Object.keys(record) as Array<keyof AuditEvent>) {
      if (record[key] === undefined) delete record[key];
    }
    try {
      Promise.resolve(sink(record)).catch(() => {
        failures++;
      });
    } catch {
      failures++;
    }
  };

  const errorFields = (error: OAuthError): Partial<AuditEvent> => ({
    error: error.error,
    errorDescription: error.error_description,
    errorDetail: error.error_detail
  });

  provider.on('authorization.success', (ctx: KoaContextWithOIDC) =>
    report('authorization-allow', ctx, { scope: paramString(ctx, 'scope') })
  );
  provider.on('authorization.error', (ctx: KoaContextWithOIDC, error: OAuthError) =>
    report('authorization-deny', ctx, errorFields(error))
  );
  provider.on('grant.success', (ctx: KoaContextWithOIDC) =>
    report('token-issue', ctx, { grantType: paramString(ctx, 'grant_type') })
  );
  provider.on('grant.error', (ctx: KoaContextWithOIDC, error: OAuthError) =>
    report(REUSE.test(error.error_detail ?? '') ? 'token-reuse' : 'token-error', ctx, {
      grantType: paramString(ctx, 'grant_type'),
      ...errorFields(error)
    })
  );
  provider.on('grant.revoked', (ctx: KoaContextWithOIDC, grantId: string) =>
    report('grant-revoke', ctx, { grantId })
  );
  const tokenDestroyed = (token: TokenLike): void =>
    report('token-revoke', undefined, {
      tokenKind: token.kind,
      clientId: token.clientId,
      accountId: token.accountId,
      grantId: token.grantId
    });
  provider.on('access_token.destroyed', tokenDestroyed);
  provider.on('refresh_token.destroyed', tokenDestroyed);
  provider.on('userinfo.error', (ctx: KoaContextWithOIDC, error: OAuthError) =>
    report('userinfo-error', ctx, errorFields(error))
  );
  provider.on('server_error', (ctx: KoaContextWithOIDC, error: Error) =>
    report('server-error', ctx, { error: 'server_error', errorDescription: error.message })
  );

  return { failures: () => failures };
}

function paramString(ctx: KoaContextWithOIDC, name: string): string | undefined {
  const value = (ctx.oidc?.params as Record<string, unknown> | undefined)?.[name];
  return typeof value === 'string' ? value : undefined;
}
