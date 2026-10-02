# oidc-auth-server

`@jwilleke/oidc-auth-server` — an OpenID Connect authorization server for Node apps, packaged so any app can embed it.

It is a thin, hardened wrapper around [node-oidc-provider](https://github.com/panva/node-oidc-provider) (MIT, OpenID Certified). The host app keeps sign-in: it says who the person is, how they signed in (`amr`, `acr`), and whether they approved the request. This package issues and checks the tokens.

Status: early. Nothing is published yet.

## What it provides

- Device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for phones, health apps and bridges that have no browser of their own
- Authorization code flow with PKCE (S256 only)
- OIDC UserInfo, discovery and JWKS
- Refresh-token rotation where the client supports it
- Dynamic client registration and client ID metadata documents
- Optional SMART on FHIR v2 scopes
- An audit hook for every grant, refresh, revocation and refusal
- A storage adapter interface, with an in-memory adapter for development and the samples

## Where the host plugs in

- __Sign-in__ — an interface the host implements: given a request, return the person, their `amr` and `acr`, and whether they approved.
- __Storage__ — an adapter for grants, sessions and clients.
- __Audit__ — a callback for each event, so the host writes it to its own audit log.

## Usage

What works today: authorization code flow with PKCE, the host sign-in seam, hashed token storage, and UserInfo. Device flow, refresh rotation, client ID metadata documents and the audit hook are tracked under [#13](https://github.com/jwilleke/oidc-auth-server/issues/13).

```ts
import { createServer } from 'node:http';
import { createAuthServer } from '@jwilleke/oidc-auth-server';

const auth = createAuthServer({
  issuer: 'https://auth.example.com',
  jwks: { keys: [privateSigningJwk] },
  cookieKeys: [process.env.OIDC_COOKIE_KEY!],
  adapter: hostAdapterFactory, // node-oidc-provider Adapter; token ids arrive hashed
  clients: [{ client_id: 'app', token_endpoint_auth_method: 'none', redirect_uris: ['…'] }],
  acrValues: ['aal1', 'aal2'],
  interactionUrl: (uid) => `/interaction/${uid}`,
  findAccount: async (accountId) => users.claimsFor(accountId) // undefined fails closed
});

createServer(async (req, res) => {
  if (!req.url?.startsWith('/interaction/')) return auth.handler(req, res);

  const pending = await auth.interactions.details(req, res);
  if (pending.prompt === 'login') {
    // The host's own sign-in runs here, then reports what it established:
    await auth.interactions.finishLogin(req, res, { accountId: 'alice', amr: ['pwd', 'otp'], acr: 'aal2' });
  } else {
    await auth.interactions.finishConsent(req, res);
  }
}).listen(9000);
```

`createAuthServer` throws before anything listens if the options are unsafe: a non-HTTPS issuer, missing private keys, short cookie keys, or no storage adapter outside `development: true`.

## Configuration

Settings follow ngdpbase's convention, under the package's own `oidc-auth-server.*` keys. [config/app-default-config.json](config/app-default-config.json) ships every default and documents each key. The host overrides them in its `app-custom-config.json`; maps merge per entry, anything else is replaced. An unknown key refuses the boot rather than being ignored.

Secrets come only from the environment — `OIDC_AUTH_SERVER_JWKS` and `OIDC_AUTH_SERVER_COOKIE_KEYS` (see [.env.example](.env.example)). Writing either into a config file refuses the boot.

```ts
import { createAuthServer, loadConfig, optionsFromConfig } from '@jwilleke/oidc-auth-server';

const config = loadConfig({ customConfigPath: 'config/app-custom-config.json' });
const auth = createAuthServer(optionsFromConfig(config, { interactionUrl, findAccount, adapter }));
```

Options passed directly to `createAuthServer` take the shipped defaults for anything left unset.

## Samples

Planned under `examples/`:

- `express` — an Express host
- `node-http` — a host on Node's built-in `http`
- `react` — a browser client (authorization code + PKCE)
- `angular` — a browser client
- `device-cli` — a device-flow client

## Development

```bash
nvm use
npm install
npm run lint
npm run typecheck
npm test
npm run build
```

Agent and contributor rules are in [AGENTS.md](AGENTS.md).

## Background

The design decisions behind this package were made for [ngdpbase](https://github.com/jwilleke/ngdpbase) and are recorded in its `docs/planning/authentication.md`.

## License

[MIT](LICENSE)
