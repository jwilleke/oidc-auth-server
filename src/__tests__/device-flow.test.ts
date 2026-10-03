import type { IncomingMessage, ServerResponse } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuditEvent } from '../audit.js';
import { createAuthServer, type AuthServer } from '../create-auth-server.js';
import { DEFAULT_DEVICE_PAGES } from '../device-flow.js';
import { baseOptions, Browser, listen } from './test-support.js';

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

type HostRoute = (auth: AuthServer, req: IncomingMessage, res: ServerResponse) => Promise<void>;

const seenDeviceFlow: boolean[] = [];
const approve: HostRoute = async (auth, req, res) => {
  const pending = await auth.interactions.details(req, res);
  seenDeviceFlow.push(pending.deviceFlow);
  if (pending.prompt === 'login') {
    await auth.interactions.finishLogin(req, res, {
      accountId: 'alice',
      amr: ['hwk', 'user'],
      acr: 'phrh'
    });
  } else {
    await auth.interactions.finishConsent(req, res);
  }
};

let host: HostRoute = approve;
let server: Awaited<ReturnType<typeof listen>>;
const audited: AuditEvent[] = [];

beforeAll(async () => {
  server = await listen((baseUrl) => {
    const auth = createAuthServer(
      baseOptions({
        issuer: baseUrl,
        acrValues: ['phrh'],
        deviceFlow: { enabled: true, throttle: { maxAttempts: 3, windowMinutes: 15 } },
        audit: (event) => {
          audited.push(event);
        },
        clients: [
          {
            client_id: 'tv',
            client_name: 'Living <Room> TV',
            token_endpoint_auth_method: 'none',
            grant_types: [DEVICE_GRANT, 'refresh_token'],
            response_types: [],
            redirect_uris: []
          }
        ]
      })
    );
    return (req, res) => {
      if (!req.url?.startsWith('/interaction/')) return auth.handler(req, res);
      return host(auth, req, res).catch((error: Error) => {
        res.statusCode = 400;
        res.end(error.message);
      });
    };
  });
});

afterAll(() => server.close());

interface DeviceStart {
  device_code: string;
  user_code: string;
  verification_uri: string;
}

async function form(path: string, params: Record<string, string>): Promise<Response> {
  return fetch(`${server.baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
}

async function startDevice(scope = 'openid offline_access'): Promise<DeviceStart> {
  const response = await form('/device/auth', { client_id: 'tv', scope });
  expect(response.status).toBe(200);
  return (await response.json()) as DeviceStart;
}

async function poll(
  deviceCode: string
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await form('/token', {
    grant_type: DEVICE_GRANT,
    device_code: deviceCode,
    client_id: 'tv'
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

const xsrfOf = (html: string): string => /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';

/** The person's browser: open the device page, enter the code, confirm, sign in through the host. */
async function enterCode(browser: Browser, userCode: string): Promise<Response> {
  const page = await browser.request('/device');
  const entered = await browser.request('/device', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ xsrf: xsrfOf(await page.text()), user_code: userCode })
  });
  return entered;
}

async function approveInBrowser(userCode: string): Promise<string> {
  const browser = new Browser(server.baseUrl);
  const confirmPage = await enterCode(browser, userCode);
  const confirmHtml = await confirmPage.text();
  expect(confirmHtml).toContain('Living &lt;Room&gt; TV');
  const { response } = await browser.follow('/device', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ xsrf: xsrfOf(confirmHtml), user_code: userCode, confirm: 'yes' })
  });
  return response.text();
}

describe('device authorization grant', () => {
  it('issues tokens to the device once the person approves through the host', async () => {
    host = approve;
    seenDeviceFlow.length = 0;
    const device = await startDevice();
    expect(device.user_code).toMatch(/^[B-DF-HJ-NP-TV-XZ]{4}-[B-DF-HJ-NP-TV-XZ]{4}$/);
    expect(device.verification_uri).toBe(`${server.baseUrl}/device`);

    expect((await poll(device.device_code)).body.error).toBe('authorization_pending');

    const success = await approveInBrowser(device.user_code);
    expect(success).toContain('Device connected');
    expect(seenDeviceFlow.length).toBeGreaterThan(0);
    expect(seenDeviceFlow.every(Boolean)).toBe(true);

    const tokens = await poll(device.device_code);
    expect(tokens.status).toBe(200);
    expect(tokens.body.access_token).toBeTruthy();
    expect(tokens.body.refresh_token).toBeTruthy();

    const userinfo = await fetch(`${server.baseUrl}/me`, {
      headers: { authorization: `Bearer ${String(tokens.body.access_token)}` }
    });
    expect(await userinfo.json()).toMatchObject({
      sub: 'alice',
      acr: 'phrh',
      amr: ['hwk', 'user']
    });
    expect(audited.some((e) => e.event === 'oidctoken-issue' && e.grantType === DEVICE_GRANT)).toBe(
      true
    );
  });

  it('answers slow_down to a device that polls too fast, without audit noise', async () => {
    const device = await startDevice();
    audited.length = 0;
    await poll(device.device_code);
    expect((await poll(device.device_code)).body.error).toBe('slow_down');
    expect(audited.filter((e) => e.event === 'oidctoken-error')).toEqual([]);
  });

  it('answers access_denied when the person refuses', async () => {
    host = (a, req, res) => a.interactions.fail(req, res, 'access_denied', 'not mine');
    const device = await startDevice();
    await approveInBrowser(device.user_code);
    expect((await poll(device.device_code)).body.error).toBe('access_denied');
  });

  it('throttles wrong user codes per client IP', async () => {
    const browser = new Browser(server.baseUrl);
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      statuses.push((await enterCode(browser, 'BCDF-GHJK')).status);
    }
    expect(statuses.slice(0, 3)).toEqual([200, 200, 200]);
    expect(statuses[3]).toBe(429);
  });
});

describe('device flow switched off', () => {
  it('mounts no device routes by default', async () => {
    const off = await listen(
      (baseUrl) => createAuthServer(baseOptions({ issuer: baseUrl })).handler
    );
    try {
      const discovery = (await (
        await fetch(`${off.baseUrl}/.well-known/openid-configuration`)
      ).json()) as Record<string, unknown>;
      expect(discovery.device_authorization_endpoint).toBeUndefined();
      expect((await fetch(`${off.baseUrl}/device`)).status).toBe(404);
    } finally {
      await off.close();
    }
  });
});

describe('default device pages', () => {
  it('escapes the client name and the code', () => {
    const html = DEFAULT_DEVICE_PAGES.userCodeConfirm({
      form: '<form></form>',
      clientName: '<script>x</script>',
      userCode: '"><img>'
    });
    expect(html).not.toContain('<script>x');
    expect(html).not.toContain('"><img>');
  });
});
