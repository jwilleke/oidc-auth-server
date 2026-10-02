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
