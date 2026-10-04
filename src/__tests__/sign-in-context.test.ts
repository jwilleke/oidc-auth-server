// The host's account lookup receives how and when the person signed in, so it can refuse a
// sign-in older than the account's last password change (ngdpbase #1592). A refusal at refresh or
// UserInfo fails closed.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SignInContext } from '../options.js';
import { ACCOUNTS, Browser } from './test-support.js';
import {
  authorize,
  exchange,
  harness,
  refresh,
  signInAlice,
  startTestServer,
  userinfo,
  type Tokens
} from './test-server.js';

const seen: Array<SignInContext | undefined> = [];
/** Accounts whose sign-ins before this epoch second are refused — a password changed then. */
const changedAt: Record<string, number> = {};

let close: () => Promise<void>;
beforeAll(async () => {
  close = await startTestServer({
    findAccount: (accountId, signIn) => {
      seen.push(signIn);
      const cutoff = changedAt[accountId];
      if (cutoff !== undefined && (signIn?.authTime ?? 0) < cutoff)
        return Promise.resolve(undefined);
      return Promise.resolve(ACCOUNTS[accountId]);
    }
  });
});
afterAll(() => close());

async function offline(): Promise<Tokens> {
  harness.host = signInAlice;
  const { redirect, verifier } = await authorize(new Browser(harness.baseUrl), {
    scope: 'openid offline_access',
    prompt: 'consent'
  });
  return (await (await exchange(redirect.searchParams.get('code')!, verifier)).json()) as Tokens;
}

describe('sign-in context for the host account lookup', () => {
  it('passes acr, amr and authTime at code exchange, refresh and UserInfo', async () => {
    delete changedAt.alice;
    seen.length = 0;
    const tokens = await offline();
    expect((await refresh(tokens.refresh_token!)).status).toBe(200);
    expect((await userinfo(tokens.access_token)).status).toBe(200);
    const withTime = seen.filter((s) => typeof s?.authTime === 'number');
    expect(withTime.length).toBeGreaterThanOrEqual(3);
    for (const s of withTime) expect(s).toMatchObject({ acr: 'aal2', amr: ['pwd', 'otp'] });
  });

  it('UserInfo still reports only acr and amr, never authTime from the context', async () => {
    delete changedAt.alice;
    const tokens = await offline();
    const claims = (await (await userinfo(tokens.access_token)).json()) as Record<string, unknown>;
    expect(claims).toMatchObject({ sub: 'alice', acr: 'aal2', amr: ['pwd', 'otp'] });
    expect(claims).not.toHaveProperty('authTime');
  });

  it('a host refusing a sign-in older than a password change makes refresh and UserInfo fail closed', async () => {
    delete changedAt.alice;
    const tokens = await offline();
    changedAt.alice = Math.floor(Date.now() / 1000) + 60;
    expect((await refresh(tokens.refresh_token!)).status).toBe(400);
    expect((await userinfo(tokens.access_token)).status).toBe(401);
  });
});
