# oidc-auth-server

`@jwilleke/oidc-auth-server` — an OpenID Connect authorization server for Node apps, packaged so any app can embed it.

It is a thin, hardened wrapper around [node-oidc-provider](https://github.com/panva/node-oidc-provider) (MIT, OpenID Certified). The host app keeps sign-in: it says who the person is, how they signed in (`amr`, `acr`), and whether they approved the request. This package issues and checks the tokens.

Status: early, pre-1.0. Released versions are listed under [Releases](https://github.com/jwilleke/oidc-auth-server/releases); publishing to npm is tracked in [#34](https://github.com/jwilleke/oidc-auth-server/issues/34). Security issues: see [SECURITY.md](SECURITY.md#reporting-a-vulnerability).

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

What works today: authorization code flow with PKCE, the host sign-in seam, hashed token storage, UserInfo, refresh token rotation with reuse detection, audience-bound tokens for registered APIs, client ID metadata documents (off by default), the device authorization grant (off by default) and the audit hook. The hardening checklist tests are tracked under [#13](https://github.com/jwilleke/oidc-auth-server/issues/13).

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
  findAccount: async (accountId) => users.claimsFor(accountId), // undefined fails closed
  audit: (event) => auditManager.record(event) // events named in oidc-auth-server.audit.events
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

const config = loadConfig({ customConfigPath: 'data/config/app-custom-config.json' });
const auth = createAuthServer(optionsFromConfig(config, { interactionUrl, findAccount, adapter }));
```

Options passed directly to `createAuthServer` take the shipped defaults for anything left unset.

### PKCE exemption for confidential clients

PKCE (S256) is required from every client. A confidential client — one that authenticates at the token endpoint with a secret or key — may opt out with `require_pkce: false` in its client metadata, for server-side apps and test tools that do not send a code challenge (the [OpenID Connect Playground](https://openidconnect.net/) is one: code flow, `client_secret` in the token request, no PKCE). A public client (`token_endpoint_auth_method: "none"`) with the exemption refuses the boot. A challenge an exempt client does send is still verified.

```json
{ "client_id": "playground", "client_secret": "…", "token_endpoint_auth_method": "client_secret_post",
  "require_pkce": false, "redirect_uris": ["https://openidconnect.net/callback"] }
```

### Device flow

Set `oidc-auth-server.device-flow.enabled` to `true`. The device calls `/device/auth`; the person opens `/device`, enters the code, and is sent to the host's interaction route like any sign-in. `auth.interactions.details()` returns `deviceFlow: true` there, so the host can require step-up before approving a device. Pass `deviceFlow.pages` to `createAuthServer` to render the code pages in the host's own markup.

## Samples

Under `examples/`:

- `node-http` — a host on Node's built-in `http`, with a stand-in sign-in and consent page, two demo accounts and the device flow on. Built: [examples/node-http](examples/node-http)
- `express` — an Express host
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

Run the example host and drive it end to end over real HTTP:

```bash
npm run dev                                   # http://localhost:9000, throwaway development keys
npm run smoke                                 # 10 checks against it: code flow, PKCE, UserInfo,
                                              # refresh rotation and reuse, code reuse, resources,
                                              # denied consent, device flow and slow_down
npm run smoke -- https://oidc.example.com     # the same checks against a deployed example host
```

The example keeps everything in memory, so it runs only with an `http` issuer (development mode). Under an `https` issuer `createAuthServer` refuses to start until a storage adapter is supplied, as it should; a public deployment needs one, plus `OIDC_AUTH_SERVER_JWKS` and `OIDC_AUTH_SERVER_COOKIE_KEYS`.

Deploying a host on bare metal, in Docker or on Kubernetes: [docs/deploying.md](docs/deploying.md).

Agent and contributor rules are in [AGENTS.md](AGENTS.md).

## Background

The design decisions behind this package were made for [ngdpbase](https://github.com/jwilleke/ngdpbase) and are recorded in its `docs/planning/authentication.md`.

## Acknowledgements

This package is built on, and shaped by, other people's work. No code was copied from any of the projects below; where their work is used, it is used as a dependency or as a published idea, credited here.

- __[node-oidc-provider](https://github.com/panva/node-oidc-provider)__ by Filip Skokan ([@panva](https://github.com/panva)), MIT. The OpenID Certified protocol implementation this package wraps: authorization code flow, PKCE, refresh rotation and reuse detection, RFC 8628, UserInfo, resource indicators, client ID metadata documents, and the special-use-address SSRF guard on outgoing requests. A runtime dependency; every protocol behaviour this package hardens or tests is ultimately its work.
- __[activescott/auth](https://github.com/activescott/auth)__ by Scott Willeke ([@activescott](https://github.com/activescott)), MIT. Its OAuth server proposal, [activescott/auth#83](https://github.com/activescott/auth/issues/83), carries the hardening list this package adopted as its review checklist and proves item by item in [src/\_\_tests\_\_/hardening.test.ts](src/__tests__/hardening.test.ts): code reuse revokes, S256-only PKCE, audience on every token, refresh reuse detection, single-use consent, hashed tokens at rest, SSRF-guarded client ID metadata documents. The broader review of its design is in ngdpbase's `docs/planning/authentication.md`.
- __[ngdpbase](https://github.com/jwilleke/ngdpbase)__ — its guiding framework and configuration conventions (a reserved key namespace, environment-only secrets, an audit event registry named `{target}-{action}`, fail closed) are followed here, and its authentication plan is the source of this package's design decisions.
- __Specifications__: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) (OAuth 2.0), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) (PKCE), [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) (device authorization grant), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) (resource indicators), [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) (`amr` values), [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), the OAuth Client ID Metadata Document draft, and NIST SP 800-63B for the assurance levels a host reports as `acr`.
- __[OpenID Connect Playground](https://openidconnect.net/)__ (Auth0) — testing against it surfaced the per-client PKCE exemption for confidential clients.

## License

[MIT](LICENSE)
