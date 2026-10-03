// A runnable host on Node's built-in http: the package mounted, plus the parts a real host
// supplies — a sign-in page, a consent page, an account lookup and an audit sink. The sign-in
// is a stand-in (pick a demo account); a real host runs its own sign-in and factors here.
//
//   npm run dev        http://localhost:9000, development keys, in-memory storage
//
// In-memory storage is development-only: under an https ISSUER createAuthServer refuses to start
// until a real storage adapter is passed.
//
// Secrets come from OIDC_AUTH_SERVER_JWKS and OIDC_AUTH_SERVER_COOKIE_KEYS. With an http issuer
// and neither set, throwaway development keys are generated at boot and every restart
// invalidates every token.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  createAuthServer,
  loadConfig,
  optionsFromConfig,
  type AuditEvent,
  type AuthServer
} from '../../src/index.js';

const PORT = Number(process.env.PORT ?? 9000);
const ISSUER = process.env.ISSUER ?? `http://localhost:${PORT}`;
const development = ISSUER.startsWith('http://');

/** Demo accounts, and how each one "signs in" — what a real host's factors would report. */
const ACCOUNTS: Record<string, { claims: Record<string, unknown>; amr: string[]; acr: string }> = {
  alice: {
    claims: { name: 'Alice Example', email: 'alice@example.com', email_verified: true },
    amr: ['pwd', 'otp'],
    acr: 'aal2'
  },
  bob: {
    claims: { name: 'Bob Example', email: 'bob@example.com', email_verified: false },
    amr: ['pwd'],
    acr: 'aal1'
  }
};

export const DEMO_CLIENTS = [
  {
    client_id: 'demo-app',
    client_name: 'Demo App',
    application_type: 'native' as const,
    token_endpoint_auth_method: 'none' as const,
    redirect_uris: ['http://127.0.0.1/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code']
  },
  {
    client_id: 'demo-device',
    client_name: 'Demo Device',
    token_endpoint_auth_method: 'none' as const,
    redirect_uris: [],
    grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
    response_types: []
  }
];

function developmentSecrets(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  if (!development || (env.OIDC_AUTH_SERVER_JWKS && env.OIDC_AUTH_SERVER_COOKIE_KEYS)) return env;
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  console.warn('[example] development keys generated; tokens die with this process');
  return {
    ...env,
    OIDC_AUTH_SERVER_JWKS:
      env.OIDC_AUTH_SERVER_JWKS ||
      JSON.stringify({
        keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'dev', use: 'sig' }]
      }),
    OIDC_AUTH_SERVER_COOKIE_KEYS:
      env.OIDC_AUTH_SERVER_COOKIE_KEYS || randomBytes(32).toString('base64url')
  };
}

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function html(res: ServerResponse, body: string): void {
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end(
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>oidc-auth-server example</title></head><body><main>${body}</main></body></html>`
  );
}

async function formBody(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString());
}

/** The host's interaction route: sign-in, then consent, both rendered and decided here. */
async function interaction(
  auth: AuthServer,
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  const pending = await auth.interactions.details(req, res);
  const action = `/interaction/${pending.uid}`;

  if (req.method === 'POST') {
    const form = await formBody(req);
    if (form.get('decision') === 'deny') {
      return auth.interactions.fail(req, res, 'access_denied', 'the person declined');
    }
    if (pending.prompt === 'login') {
      const account = ACCOUNTS[form.get('account') ?? ''];
      if (!account) return auth.interactions.fail(req, res, 'access_denied', 'unknown account');
      return auth.interactions.finishLogin(req, res, {
        accountId: form.get('account')!,
        amr: account.amr,
        acr: account.acr
      });
    }
    return auth.interactions.finishConsent(req, res);
  }

  const device = pending.deviceFlow
    ? '<p><strong>A device is asking.</strong> A real host requires step-up here.</p>'
    : '';
  if (pending.prompt === 'login') {
    return html(
      res,
      `<h1>Sign in</h1>${device}<form method="post" action="${action}"><label>Account <select name="account">${Object.keys(
        ACCOUNTS
      )
        .map((id) => `<option>${id}</option>`)
        .join(
          ''
        )}</select></label><button name="decision" value="login">Sign in</button><button name="decision" value="deny">Cancel</button></form>`
    );
  }
  return html(
    res,
    `<h1>Allow access?</h1>${device}<p><strong>${escapeHtml(pending.clientId)}</strong> asks for <code>${escapeHtml(pending.scope)}</code> for ${escapeHtml(pending.accountId ?? '')}.</p><form method="post" action="${action}"><button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></form>`
  );
}

export function startExample(
  port = PORT
): Promise<{ close: () => Promise<void>; auth: AuthServer }> {
  const config = loadConfig({
    customConfigPath: 'config/app-custom-config.json',
    customConfig: {
      'oidc-auth-server.issuer': ISSUER,
      'oidc-auth-server.development': development,
      'oidc-auth-server.clients': DEMO_CLIENTS,
      'oidc-auth-server.acr-values': ['aal1', 'aal2'],
      'oidc-auth-server.device-flow.enabled': true
    },
    env: developmentSecrets(process.env)
  });

  const auth = createAuthServer(
    optionsFromConfig(config, {
      interactionUrl: (uid) => `/interaction/${uid}`,
      findAccount: (accountId) => Promise.resolve(ACCOUNTS[accountId]?.claims),
      audit: (event: AuditEvent) => console.log(`[audit] ${JSON.stringify(event)}`)
    })
  );

  const server = createServer((req, res) => {
    const route = req.url?.startsWith('/interaction/')
      ? interaction(auth, req, res)
      : auth.handler(req, res);
    route.catch((error: Error) => {
      res.statusCode = 400;
      html(res, `<h1>Request failed</h1><p>${escapeHtml(error.message)}</p>`);
    });
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      console.log(`[example] ${ISSUER} listening on :${port}`);
      resolve({ auth, close: () => new Promise((done) => server.close(() => done())) });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) void startExample();
