// Drives a running server over real HTTP, end to end, the way a client and a person would.
//
//   npm run smoke                                   against http://localhost:9000
//   npm run smoke -- https://oidc.example.com       against any deployment of the example host
//
// It signs in through the example host's pages, so it needs that host (or one whose sign-in
// and consent forms take the same fields). Exits non-zero on any failure.

import { Browser, decodeJwt, pkcePair } from '../../src/__tests__/test-support.js';

const BASE = (process.argv[2] ?? process.env.SMOKE_URL ?? 'http://localhost:9000').replace(
  /\/$/,
  ''
);
const REDIRECT = 'http://127.0.0.1/callback';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

type Json = Record<string, unknown>;
const results: Array<{ name: string; ok: boolean; detail?: string }> = [];

async function check(name: string, run: () => Promise<void>): Promise<void> {
  try {
    await run();
    results.push({ name, ok: true });
  } catch (error) {
    results.push({ name, ok: false, detail: (error as Error).message });
  }
}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function post(
  path: string,
  params: Record<string, string>,
  headers = {}
): Promise<{ status: number; body: Json }> {
  const response = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(params)
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text.startsWith('{') ? (JSON.parse(text) as Json) : { text }
  };
}

const formAction = (html: string): string =>
  /<form method="post" action="([^"]+)"/.exec(html)?.[1] ?? '';
const xsrfOf = (html: string): string => /name="xsrf" value="([^"]+)"/.exec(html)?.[1] ?? '';

/** Submit the example host's sign-in, then consent, from whatever page the flow is on. */
async function signInAndConsent(
  browser: Browser,
  page: { response: Response; url: string },
  account: string,
  consent = 'allow'
): Promise<string> {
  let current = page;
  for (let step = 0; step < 4 && current.url.includes('/interaction/'); step++) {
    const pageHtml = await current.response.text();
    const isLogin = pageHtml.includes('<h1>Sign in</h1>');
    current = await browser.follow(formAction(pageHtml), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(isLogin ? { account, decision: 'login' } : { decision: consent })
    });
  }
  return current.url;
}

async function codeFlow(
  account: string,
  extra: Record<string, string> = {}
): Promise<{ redirect: URL; verifier: string }> {
  const { verifier, challenge } = pkcePair();
  const browser = new Browser(BASE);
  const query = new URLSearchParams({
    client_id: 'demo-app',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile email offline_access',
    prompt: 'consent',
    state: 'smoke',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra
  });
  const start = await browser.follow(`/auth?${query.toString()}`);
  return { redirect: new URL(await signInAndConsent(browser, start, account)), verifier };
}

async function exchange(code: string, verifier: string): Promise<{ status: number; body: Json }> {
  return post('/token', {
    grant_type: 'authorization_code',
    client_id: 'demo-app',
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier
  });
}

const refresh = (token: string): Promise<{ status: number; body: Json }> =>
  post('/token', { grant_type: 'refresh_token', client_id: 'demo-app', refresh_token: token });

const userinfo = async (token: string): Promise<{ status: number; body: Json }> => {
  const response = await fetch(`${BASE}/me`, { headers: { authorization: `Bearer ${token}` } });
  return {
    status: response.status,
    body: response.status === 200 ? ((await response.json()) as Json) : {}
  };
};

async function main(): Promise<void> {
  console.log(`smoke: ${BASE}`);

  await check('discovery: issuer, code flow only, S256 only, device endpoint', async () => {
    const d = (await (await fetch(`${BASE}/.well-known/openid-configuration`)).json()) as Json;
    expect(d.issuer === BASE, `issuer ${String(d.issuer)} is not ${BASE}`);
    expect(JSON.stringify(d.response_types_supported) === '["code"]', 'response types');
    expect(JSON.stringify(d.code_challenge_methods_supported) === '["S256"]', 'PKCE methods');
    expect(typeof d.device_authorization_endpoint === 'string', 'no device endpoint');
  });

  await check('jwks publishes no private key material', async () => {
    const jwks = (await (await fetch(`${BASE}/jwks`)).json()) as { keys: Json[] };
    expect(jwks.keys.length > 0, 'no keys');
    expect(
      jwks.keys.every((k) => !('d' in k) && !('p' in k)),
      'private key part published'
    );
  });

  await check('authorization without PKCE is refused', async () => {
    const browser = new Browser(BASE);
    const q = new URLSearchParams({
      client_id: 'demo-app',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid'
    });
    const { url } = await browser.follow(`/auth?${q.toString()}`);
    expect(new URL(url).searchParams.get('error') === 'invalid_request', `got ${url}`);
  });

  let tokens: Json = {};
  await check('code flow: sign in, consent, tokens; ID token carries amr and acr', async () => {
    const { redirect, verifier } = await codeFlow('alice');
    const code = redirect.searchParams.get('code');
    expect(code, `no code: ${redirect.href}`);
    const response = await exchange(code, verifier);
    expect(response.status === 200, `token ${response.status} ${JSON.stringify(response.body)}`);
    tokens = response.body;
    const id = decodeJwt(String(tokens.id_token));
    expect(id.sub === 'alice', 'sub');
    expect(
      JSON.stringify(id.amr) === '["pwd","otp"]' && id.acr === 'aal2',
      `amr/acr ${JSON.stringify(id)}`
    );
    expect(tokens.refresh_token, 'no refresh token');
  });

  await check('userinfo: scoped claims plus acr and amr', async () => {
    const { status, body } = await userinfo(String(tokens.access_token));
    expect(status === 200, `status ${status}`);
    expect(body.email === 'alice@example.com' && body.name === 'Alice Example', 'claims');
    expect(body.acr === 'aal2', 'acr');
  });

  await check('refresh rotates; replaying the old one revokes the grant', async () => {
    const first = String(tokens.refresh_token);
    const second = await refresh(first);
    expect(second.status === 200 && second.body.refresh_token !== first, 'no rotation');
    const replay = await refresh(first);
    expect(replay.status === 400 && replay.body.error === 'invalid_grant', 'replay accepted');
    expect(
      (await refresh(String(second.body.refresh_token))).status === 400,
      'grant survived replay'
    );
    expect(
      (await userinfo(String(second.body.access_token))).status === 401,
      'access token survived'
    );
  });

  await check('authorization code works once; reuse revokes its tokens', async () => {
    const { redirect, verifier } = await codeFlow('bob');
    const code = redirect.searchParams.get('code')!;
    const first = await exchange(code, verifier);
    expect(first.status === 200, 'first exchange');
    expect((await exchange(code, verifier)).body.error === 'invalid_grant', 'second exchange');
    expect((await userinfo(String(first.body.access_token))).status === 401, 'tokens survived');
  });

  await check('unregistered resource is refused', async () => {
    const { redirect } = await codeFlow('alice', {
      resource: 'https://not-registered.example.com'
    });
    expect(redirect.searchParams.get('error') === 'invalid_target', `got ${redirect.href}`);
  });

  await check('denied consent ends with access_denied', async () => {
    const { verifier: _v, challenge } = pkcePair();
    const browser = new Browser(BASE);
    const q = new URLSearchParams({
      client_id: 'demo-app',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    const start = await browser.follow(`/auth?${q.toString()}`);
    const url = new URL(await signInAndConsent(browser, start, 'alice', 'deny'));
    expect(url.searchParams.get('error') === 'access_denied', `got ${url.href}`);
  });

  await check('device flow: code, approval through the host, tokens; slow_down', async () => {
    const start = await post('/device/auth', {
      client_id: 'demo-device',
      scope: 'openid offline_access'
    });
    expect(start.status === 200, `device auth ${start.status}`);
    const deviceCode = String(start.body.device_code);
    const userCode = String(start.body.user_code);
    const pollOnce = (): Promise<{ status: number; body: Json }> =>
      post('/token', {
        grant_type: DEVICE_GRANT,
        client_id: 'demo-device',
        device_code: deviceCode
      });
    expect((await pollOnce()).body.error === 'authorization_pending', 'not pending');
    expect((await pollOnce()).body.error === 'slow_down', 'no slow_down');

    const browser = new Browser(BASE);
    const page = await (await browser.request('/device')).text();
    const confirm = await (
      await browser.request('/device', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ xsrf: xsrfOf(page), user_code: userCode })
      })
    ).text();
    const afterConfirm = await browser.follow('/device', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ xsrf: xsrfOf(confirm), user_code: userCode, confirm: 'yes' })
    });
    const done = await signInAndConsent(browser, afterConfirm, 'bob');
    expect(done.includes('/device'), `ended at ${done}`);

    await new Promise((resolve) => setTimeout(resolve, 5000));
    const issued = await pollOnce();
    expect(issued.status === 200, `poll ${issued.status} ${JSON.stringify(issued.body)}`);
    const info = await userinfo(String(issued.body.access_token));
    expect(
      info.body.sub === 'bob' && info.body.acr === 'aal1',
      `userinfo ${JSON.stringify(info.body)}`
    );
  });

  for (const r of results)
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `\n      ${r.detail}` : ''}`);
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed === 0 ? 0 : 1);
}

void main();
