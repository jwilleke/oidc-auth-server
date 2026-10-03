import { readFileSync } from 'node:fs';
import type { ClientMetadata, JWKS } from 'oidc-provider';
import type { AuditEventDefinition } from './audit.js';
import type { AuthServerOptions, ResourceServer, Ttl } from './options.js';

/** A flat configuration: `oidc-auth-server.*` keys to values, comments removed. */
export type Config = Record<string, unknown>;

const PREFIX = 'oidc-auth-server.';
const ENV_KEYS = `${PREFIX}config.env-keys`;

let shipped: Config | undefined;

/** The shipped `config/app-default-config.json`, read once. The one home of every default. */
export function defaultConfig(): Config {
  if (!shipped) {
    const raw = JSON.parse(
      readFileSync(new URL('../config/app-default-config.json', import.meta.url), 'utf8')
    ) as Config;
    shipped = withoutComments(raw);
  }
  return structuredClone(shipped);
}

function withoutComments(config: Config): Config {
  return Object.fromEntries(Object.entries(config).filter(([key]) => !key.startsWith('_comment')));
}

function isMap(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface LoadConfigOptions {
  /** Path to the host's app-custom-config.json. A missing file is not an error. */
  customConfigPath?: string;
  /** The host's overrides, when it already holds them in memory. Applied after the file. */
  customConfig?: Config;
  /** Where environment-owned keys are read from. Defaults to `process.env`. */
  env?: Record<string, string | undefined>;
}

/**
 * Shipped defaults ⊕ the host's custom config ⊕ the environment. Maps merge per entry; any other
 * value is replaced whole. Throws on an unknown key (a typo would otherwise be silently ignored)
 * and on an environment-owned key set in a file (a secret must not live in one).
 */
export function loadConfig(options: LoadConfigOptions = {}): Config {
  const config = defaultConfig();
  const envKeys = (config[ENV_KEYS] ?? {}) as Record<string, string>;
  const problems: string[] = [];

  const layers: Config[] = [];
  if (options.customConfigPath) {
    try {
      layers.push(JSON.parse(readFileSync(options.customConfigPath, 'utf8')) as Config);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        problems.push(`${options.customConfigPath} could not be read: ${(error as Error).message}`);
      }
    }
  }
  if (options.customConfig) layers.push(options.customConfig);

  for (const layer of layers) {
    for (const [key, value] of Object.entries(withoutComments(layer))) {
      if (!key.startsWith(PREFIX)) continue;
      if (key in envKeys) {
        problems.push(
          `${key} is owned by the environment (${envKeys[key]}); remove it from the file`
        );
      } else if (!(key in config)) {
        problems.push(`${key} is not a known setting`);
      } else if (isMap(config[key]) && isMap(value)) {
        config[key] = { ...config[key], ...value };
      } else {
        config[key] = value;
      }
    }
  }

  const env = options.env ?? process.env;
  for (const [key, variable] of Object.entries(envKeys)) {
    const value = env[variable];
    if (value !== undefined && value !== '') config[key] = value;
  }

  if (problems.length > 0) {
    throw new Error(`oidc-auth-server configuration refused:\n- ${problems.join('\n- ')}`);
  }
  return config;
}

/** The host's code-level parts: what a config file cannot hold. */
export type HostCallbacks = Pick<AuthServerOptions, 'interactionUrl' | 'findAccount' | 'adapter'>;

/** Turn a loaded config and the host's callbacks into `createAuthServer` options. */
export function optionsFromConfig(config: Config, callbacks: HostCallbacks): AuthServerOptions {
  const get = <T>(key: string): T => config[`${PREFIX}${key}`] as T;

  let jwks: JWKS = { keys: [] };
  const rawJwks = get<unknown>('jwks');
  if (typeof rawJwks === 'string') {
    try {
      jwks = JSON.parse(rawJwks) as JWKS;
    } catch {
      throw new Error('oidc-auth-server configuration refused:\n- jwks is not valid JSON');
    }
  }
  const rawCookieKeys = get<unknown>('cookie-keys');
  const cookieKeys = typeof rawCookieKeys === 'string' ? splitList(rawCookieKeys) : [];

  return {
    ...callbacks,
    issuer: get<string>('issuer'),
    development: get<boolean>('development'),
    jwks,
    cookieKeys,
    clients: get<ClientMetadata[]>('clients'),
    acrValues: get<string[]>('acr-values'),
    scopeClaims: get<Record<string, string[]>>('scope-claims'),
    ttl: ttlFromConfig(config),
    resourceServers: resourceServersFromConfig(get('resource-servers')),
    auditEvents: auditEventsFromConfig(get('audit.events')),
    deviceFlow: {
      enabled: get<boolean>('device-flow.enabled'),
      userCodeCharset: get<'base-20' | 'digits'>('device-flow.user-code-charset'),
      userCodeMask: get<string>('device-flow.user-code-mask'),
      throttle: {
        maxAttempts: get<number>('device-flow.throttle.max-attempts'),
        windowMinutes: get<number>('device-flow.throttle.window-minutes')
      }
    },
    clientIdMetadataDocument: {
      enabled: get<boolean>('client-id-metadata-document.enabled'),
      allowedHosts: get<string[]>('client-id-metadata-document.allowed-hosts')
    }
  };
}

/** `oidc-auth-server.audit.events` by option name; null stays null (the entry is removed). */
export function auditEventsFromConfig(raw: unknown): Record<string, AuditEventDefinition | null> {
  const events: Record<string, AuditEventDefinition | null> = {};
  for (const [name, entry] of Object.entries((raw ?? {}) as Record<string, unknown>)) {
    if (entry === null) {
      events[name] = null;
      continue;
    }
    const settings = entry as Record<string, unknown>;
    events[name] = {
      onFailure: settings['on-failure'] as AuditEventDefinition['onFailure'],
      description: settings.description as string,
      enabled: settings.enabled as boolean | undefined
    };
  }
  return events;
}

function resourceServersFromConfig(raw: unknown): Record<string, ResourceServer> {
  const servers: Record<string, ResourceServer> = {};
  for (const [indicator, entry] of Object.entries((raw ?? {}) as Record<string, unknown>)) {
    // null removes an entry, as in ngdpbase: a host can drop a shipped or inherited server.
    if (entry === null) continue;
    const settings = entry as Record<string, unknown>;
    servers[indicator] = {
      scope: settings.scope as string,
      accessTokenFormat: settings['access-token-format'] as ResourceServer['accessTokenFormat'],
      accessTokenTtl: settings['access-token-ttl'] as number | undefined
    };
  }
  return servers;
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** The `oidc-auth-server.ttl.*` keys, by their option name. */
export function ttlFromConfig(config: Config): Ttl {
  const get = (key: string): number => config[`${PREFIX}ttl.${key}`] as number;
  return {
    accessToken: get('access-token'),
    authorizationCode: get('authorization-code'),
    idToken: get('id-token'),
    interaction: get('interaction'),
    session: get('session'),
    grant: get('grant'),
    refreshToken: get('refresh-token'),
    deviceCode: get('device-code')
  };
}
