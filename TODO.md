---
title: TODO
description: Priority bands for oidc-auth-server.
last_updated: "2026-10-02"
---

# TODO

<!-- RESUME:START -->
## ▶ Resume here — 2026-10-09

- Last worked on: npm publishing. 0.2.0 was published by hand (account 2FA blocked a token-based CI publish), Trusted Publisher configured; later sessions released v0.3.0, v0.3.1 and v0.4.0 from CI with no token (path mount #32, issuer-host fix, types, findAccount receives the sign-in)
- Branch / state: master, clean, in sync with origin, 0 stashes
- Running / in-flight: none — CI and Release green at dc6fff0; example server stopped
- Parked / half-done: none
- Next steps:
  - #42 (P0): prove state, nonce, single-use PKCE code and email_verified handling with tests
  - Close the in-review items #32, #39, #40, then epic #41 (repo is public, settings on)
  - #27: decide where the standalone server's users sign in — unblocks epic #31
  - #43: back-channel logout
- Blockers / significant notes: SSH port 22 to GitHub times out on this machine — push over HTTPS with `gh auth git-credential`. Revoke the unused npm tokens from 2026-10-03. The ngdpbase checkout is shared with another session (OidcManager epic ngdpbase#1578)
<!-- RESUME:END -->
<!-- KIT:START — managed by mjs-project-template; add your own sections below KIT:END -->

## 🔴 P0 — Security & Critical

- [#42](https://github.com/jwilleke/oidc-auth-server/issues/42) — [BUG] Prove state, nonce, single-use PKCE code and email_verified handling with tests

## 🟣 Epics

- [#41](https://github.com/jwilleke/oidc-auth-server/issues/41) — [EPIC] Make the repository and releases public
- [#31](https://github.com/jwilleke/oidc-auth-server/issues/31) — [EPIC] Deploy oidc.example.com via mj-infra-flux

## 🟠 P1

- [#43](https://github.com/jwilleke/oidc-auth-server/issues/43) — [FEATURE] Back-Channel Logout (and RP-Initiated end-session) so logging out reaches every app

## 🟡 P2

- [#26](https://github.com/jwilleke/oidc-auth-server/issues/26) — [SECURITY] braces — stack-exhaustion DoS via nested patterns (dev tooling)

## 🔵 In review

- [#40](https://github.com/jwilleke/oidc-auth-server/issues/40) — Make the repository public
- [#39](https://github.com/jwilleke/oidc-auth-server/issues/39) — Enable public-repo security settings
- [#32](https://github.com/jwilleke/oidc-auth-server/issues/32) — Tests for an issuer mounted under a path (`<host>/oidc`)

## ⏸ Deferred

*None.*

## ❓ Needs triage

- [#30](https://github.com/jwilleke/oidc-auth-server/issues/30) — Deploy oidc.example.com through mj-infra-flux
- [#29](https://github.com/jwilleke/oidc-auth-server/issues/29) — Release workflow: publish ghcr.io/jwilleke/oidc-auth-server:X.Y.Z on each release tag
- [#28](https://github.com/jwilleke/oidc-auth-server/issues/28) — PostgreSQL storage adapter for the production host
- [#27](https://github.com/jwilleke/oidc-auth-server/issues/27) — Production host for oidc.example.com: decide where people sign in

<!-- KIT:END -->
