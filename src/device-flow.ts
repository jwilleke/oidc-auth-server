import type Provider from 'oidc-provider';
import type { Configuration, KoaContextWithOIDC } from 'oidc-provider';

type DeviceFlowFeature = NonNullable<NonNullable<Configuration['features']>['deviceFlow']>;

export interface UserCodeThrottle {
  record(ip: string): void;
  blocked(ip: string): boolean;
  retryAfterSeconds(ip: string): number;
}

/** What went wrong with the user code the person entered, for the input page to say. */
export type UserCodeProblem = 'wrong-code' | 'expired' | 'already-used' | 'aborted' | 'error';

/**
 * Page markup for the device flow. `form` is the provider's form, holding the CSRF token; the
 * page must include it unchanged. Defaults are deliberately plain; a host supplies its own look.
 */
export interface DevicePages {
  /** Asks for the user code. The submit button targets form id `op.deviceInputForm`. */
  userCodeInput(input: { form: string; problem?: UserCodeProblem }): string;
  /** Asks the person to confirm the code their device shows. Submit targets `op.deviceConfirmForm`. */
  userCodeConfirm(input: { form: string; clientName: string; userCode: string }): string;
  /** Shown after approval; the device picks up its tokens on its next poll. */
  success(input: { clientName: string }): string;
}

export interface DeviceFlowOptions {
  enabled: boolean;
  userCodeCharset?: 'base-20' | 'digits';
  userCodeMask?: string;
  /** Wrong user codes allowed per client IP within the window before the page answers 429. */
  throttle?: { maxAttempts: number; windowMinutes: number };
  pages?: Partial<DevicePages>;
}

const escapeHtml = (value: string): string =>
  value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string
  );

const page = (title: string, body: string): string =>
  `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head><body><main><h1>${title}</h1>${body}</main></body></html>`;

const PROBLEM_TEXT: Record<UserCodeProblem, string> = {
  'wrong-code': 'That code was not recognised. Check your device and try again.',
  expired: 'That code has expired. Start again on your device.',
  'already-used': 'That code has already been used.',
  aborted: 'The sign-in was cancelled.',
  error: 'Something went wrong. Try again.'
};

export const DEFAULT_DEVICE_PAGES: DevicePages = {
  userCodeInput: ({ form, problem }) =>
    page(
      'Connect a device',
      `<p>${problem ? PROBLEM_TEXT[problem] : 'Enter the code shown on your device.'}</p>${form}<button type="submit" form="op.deviceInputForm">Continue</button>`
    ),
  userCodeConfirm: ({ form, clientName, userCode }) =>
    page(
      'Confirm the code',
      `<p><strong>${escapeHtml(clientName)}</strong> is asking to connect.</p><p>Make sure your device shows <code>${escapeHtml(userCode)}</code>.</p>${form}<button type="submit" form="op.deviceConfirmForm">Continue</button>`
    ),
  success: ({ clientName }) =>
    page(
      'Device connected',
      `<p>${escapeHtml(clientName)} is connected. You can close this page and return to your device.</p>`
    )
};

const PROBLEMS: Record<string, UserCodeProblem> = {
  NotFoundError: 'wrong-code',
  ExpiredError: 'expired',
  AlreadyUsedError: 'already-used',
  AbortedError: 'aborted'
};

/** Errors that mean someone entered a code that does not work — the ones worth counting. */
const GUESSES = new Set(['NotFoundError', 'ExpiredError', 'AlreadyUsedError']);

/** Counts wrong user codes per client IP in a sliding window. In process memory: per instance. */
export function userCodeThrottle(maxAttempts: number, windowMinutes: number): UserCodeThrottle {
  const windowMs = windowMinutes * 60_000;
  const attempts = new Map<string, number[]>();
  const recent = (ip: string): number[] => {
    const cutoff = Date.now() - windowMs;
    const kept = (attempts.get(ip) ?? []).filter((at) => at > cutoff);
    if (kept.length === 0) attempts.delete(ip);
    else attempts.set(ip, kept);
    return kept;
  };
  return {
    record(ip: string): void {
      attempts.set(ip, [...recent(ip), Date.now()]);
    },
    blocked(ip: string): boolean {
      return recent(ip).length >= maxAttempts;
    },
    retryAfterSeconds(ip: string): number {
      const oldest = recent(ip)[0];
      return oldest ? Math.max(1, Math.ceil((oldest + windowMs - Date.now()) / 1000)) : 0;
    }
  };
}

const clientNameOf = (ctx: KoaContextWithOIDC): string =>
  ctx.oidc.client?.clientName ?? ctx.oidc.client?.clientId ?? 'A device';

/**
 * node-oidc-provider's deviceFlow feature settings: the three page sources, wired to the host's
 * pages (or the defaults), and wrong codes counted toward the throttle.
 */
export function deviceFlowFeature(
  options: DeviceFlowOptions,
  throttle: UserCodeThrottle
): DeviceFlowFeature {
  const pages = { ...DEFAULT_DEVICE_PAGES, ...options.pages };
  return {
    enabled: options.enabled,
    charset: options.userCodeCharset ?? 'base-20',
    mask: options.userCodeMask ?? '****-****',
    userCodeInputSource: (ctx: KoaContextWithOIDC, form: string, _out: unknown, err?: Error) => {
      if (err && GUESSES.has(err.name)) throttle.record(ctx.ip);
      const problem = err ? (PROBLEMS[err.name] ?? 'error') : undefined;
      ctx.type = 'html';
      ctx.body = pages.userCodeInput({ form, problem });
    },
    userCodeConfirmSource: (
      ctx: KoaContextWithOIDC,
      form: string,
      _client: unknown,
      _deviceInfo: unknown,
      userCode: string
    ) => {
      ctx.type = 'html';
      ctx.body = pages.userCodeConfirm({ form, clientName: clientNameOf(ctx), userCode });
    },
    successSource: (ctx: KoaContextWithOIDC) => {
      ctx.type = 'html';
      ctx.body = pages.success({ clientName: clientNameOf(ctx) });
    }
  };
}

/** Answer 429 to a user-code submission from a client IP over the throttle limit. */
export function applyUserCodeThrottle(provider: Provider, throttle: UserCodeThrottle): void {
  provider.use(async (ctx, next) => {
    if (ctx.method === 'POST' && ctx.path.endsWith('/device') && throttle.blocked(ctx.ip)) {
      ctx.status = 429;
      ctx.set('retry-after', String(throttle.retryAfterSeconds(ctx.ip)));
      ctx.type = 'text';
      ctx.body = 'Too many wrong codes. Wait, then try again.';
      return;
    }
    await next();
  });
}

/** RFC 8628 §3.2: with no interval in the device authorization response, clients wait 5 seconds. */
export const POLLING_INTERVAL_SECONDS = 5;

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Answer slow_down (RFC 8628 §3.5) to a device that polls again within the interval. node-oidc-
 * provider defines the error but never sends it. Only a pending answer is rewritten: a device
 * whose code was approved gets its tokens however early it asks. In process memory: per instance.
 */
export function applyPollingInterval(provider: Provider, maxAgeSeconds: number): void {
  const lastPoll = new Map<string, number>();
  const intervalMs = POLLING_INTERVAL_SECONDS * 1000;

  provider.use(async (ctx, next) => {
    await next();
    const oidc = (ctx as Partial<KoaContextWithOIDC>).oidc;
    const params = oidc?.params as Record<string, unknown> | undefined;
    const body = ctx.body as { error?: string } | undefined;
    if (
      oidc?.route !== 'token' ||
      params?.grant_type !== DEVICE_GRANT ||
      typeof params.device_code !== 'string' ||
      body?.error !== 'authorization_pending'
    ) {
      return;
    }
    const now = Date.now();
    const previous = lastPoll.get(params.device_code);
    lastPoll.set(params.device_code, now);
    if (previous !== undefined && now - previous < intervalMs) {
      ctx.body = { error: 'slow_down', error_description: 'polling too fast' };
    }
    if (lastPoll.size > 1000) {
      for (const [code, at] of lastPoll) {
        if (now - at > maxAgeSeconds * 1000) lastPoll.delete(code);
      }
    }
  });
}
