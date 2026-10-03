---
title: Deploying
description: Running a host that embeds oidc-auth-server on bare metal, in Docker and on Kubernetes.
---

# Deploying

`oidc-auth-server` is a library. What you deploy is the __host__ that embeds it — [ngdpbase](https://github.com/jwilleke/ngdpbase), or your own app — because the host owns sign-in, storage and audit. The examples below run a host whose entry point is `server.js`; substitute yours.

[examples/node-http](../examples/node-http) is a development host only: it keeps everything in memory, so under an `https` issuer `createAuthServer` refuses to start until a real storage adapter is supplied.

The first deployment target is Kubernetes. The same requirements hold everywhere; only the wiring differs.

## What every deployment needs

| Need | Where it comes from |
| --- | --- |
| An `https` issuer, the public URL clients see, including any path prefix | `oidc-auth-server.issuer` in the host's `app-custom-config.json` |
| Signing keys (a JWK Set with private keys) | `OIDC_AUTH_SERVER_JWKS` — environment only |
| Cookie keys, each 32+ characters | `OIDC_AUTH_SERVER_COOKIE_KEYS`, comma-separated — environment only |
| A storage adapter shared by every instance | Host code: the `adapter` option. Memory is refused outside development |
| `trust-proxy: true` when TLS ends at a proxy, ingress or load balancer | `oidc-auth-server.trust-proxy` |
| The proxy forwarding `X-Forwarded-Proto` and `X-Forwarded-For` | Proxy configuration |

With an `https` issuer, a request that reaches the process over plain HTTP without a trusted `X-Forwarded-Proto: https` is refused with a message naming `trust-proxy`. That is deliberate: serving it would mean cookies without `Secure` and the proxy's address recorded as every client's IP. Discovery and JWKS are the exception, so health probes can use plain HTTP.

Every setting, with its default and reason, is documented in [config/app-default-config.json](../config/app-default-config.json).

### Generating the secrets

```bash
# Signing key: one RSA key as a JWK Set, on one line, for OIDC_AUTH_SERVER_JWKS
node -e "const {generateKeyPairSync,randomUUID}=require('node:crypto');const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});console.log(JSON.stringify({keys:[{...privateKey.export({format:'jwk'}),kid:randomUUID(),use:'sig',alg:'RS256'}]}))"

# Cookie key, for OIDC_AUTH_SERVER_COOKIE_KEYS
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Every instance of one deployment uses the same values. Store them in your secret manager, never in a config file — `loadConfig` refuses either key if a file sets it.

### Rotating keys

- __Signing keys:__ put the new key first in the set and keep the old one until every token it signed has expired (the longest of `ttl.id-token`, `ttl.access-token` for JWT resource tokens). Then remove it. Clients refetch `/jwks` when they meet an unknown `kid`.
- __Cookie keys:__ the first key signs, the rest still verify. Prepend the new key, keep the old one for a session lifetime (`ttl.session`), then drop it.

### More than one instance

State that must survive an instance going away lives in the storage adapter, so instances need no sticky sessions. Two protections are kept in process memory and therefore count per instance: the device flow's wrong-code throttle and its `slow_down` polling check. With three replicas, a guesser gets up to three times `device-flow.throttle.max-attempts` per window. Keep replicas modest, or put a rate limit on `POST /device` at the proxy.

### Health checks

`GET /.well-known/openid-configuration` answers `200` once the server is up and works over plain HTTP from inside the cluster or host. Use it for liveness and readiness.

### Checking a deployment

```bash
curl -fsS https://oidc.example.com/.well-known/openid-configuration | jq .issuer
```

The issuer printed must equal the configured one, character for character. `npm run smoke -- https://oidc.example.com` runs the full end-to-end checks, but only against a deployment of the example host, since it signs in through that host's pages.

## Bare metal

A host process under systemd, behind nginx for TLS.

`/etc/oidc-auth-server/env` (mode `600`, owned by root):

```bash
NODE_ENV=production
PORT=9000
OIDC_AUTH_SERVER_JWKS={"keys":[…]}
OIDC_AUTH_SERVER_COOKIE_KEYS=…
```

`/opt/oidc-host/data/config/app-custom-config.json`:

```json
{
  "oidc-auth-server.issuer": "https://oidc.example.com",
  "oidc-auth-server.trust-proxy": true
}
```

`/etc/systemd/system/oidc-host.service`:

```ini
[Unit]
Description=OIDC host
After=network-online.target
Wants=network-online.target

[Service]
User=oidc
Group=oidc
WorkingDirectory=/opt/oidc-host
EnvironmentFile=/etc/oidc-auth-server/env
ExecStart=/usr/bin/node server.js
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

nginx, terminating TLS and forwarding to the process on `127.0.0.1:9000`:

```nginx
server {
  listen 443 ssl;
  http2 on;
  server_name oidc.example.com;
  ssl_certificate     /etc/letsencrypt/live/oidc.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/oidc.example.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }
}
```

Bind the process to `127.0.0.1` so nothing reaches it except through nginx — `trust-proxy` makes the forwarded headers authoritative, and a client reaching the process directly could forge them.

## Docker

`Dockerfile` for the host app:

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY config ./config
USER node
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:9000/.well-known/openid-configuration >/dev/null || exit 1
CMD ["node", "dist/server.js"]
```

Per-instance settings live in `data/config/app-custom-config.json`, mounted at run time rather than baked into the image; secrets are passed as environment variables and never baked in.

`docker-compose.yml`, with Traefik in front for TLS:

```yaml
services:
  oidc:
    image: ghcr.io/example/oidc-host:1.2.0
    restart: unless-stopped
    env_file: .env # OIDC_AUTH_SERVER_JWKS, OIDC_AUTH_SERVER_COOKIE_KEYS
    volumes:
      - ./app-custom-config.json:/app/data/config/app-custom-config.json:ro
    labels:
      - traefik.enable=true
      - traefik.http.routers.oidc.rule=Host(`oidc.example.com`)
      - traefik.http.routers.oidc.entrypoints=websecure
      - traefik.http.routers.oidc.tls.certresolver=letsencrypt
      - traefik.http.services.oidc.loadbalancer.server.port=9000
```

Traefik sets `X-Forwarded-Proto` and `X-Forwarded-For` by default, so `app-custom-config.json` sets `"oidc-auth-server.trust-proxy": true`. Publish no host port for the `oidc` service: only Traefik should reach it.

## Kubernetes

Plain manifests that work on k8s and k3s. k3s ships Traefik as its ingress controller; with ingress-nginx, change `ingressClassName`. Certificates come from cert-manager here; use whatever your cluster issues.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oidc-secrets
type: Opaque
stringData:
  OIDC_AUTH_SERVER_JWKS: '{"keys":[…]}'
  OIDC_AUTH_SERVER_COOKIE_KEYS: '…'
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: oidc-config
data:
  app-custom-config.json: |
    {
      "oidc-auth-server.issuer": "https://oidc.example.com",
      "oidc-auth-server.trust-proxy": true
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oidc
spec:
  replicas: 2
  selector:
    matchLabels: { app: oidc }
  template:
    metadata:
      labels: { app: oidc }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: oidc
          image: ghcr.io/example/oidc-host:1.2.0
          ports:
            - containerPort: 9000
          envFrom:
            - secretRef: { name: oidc-secrets }
          env:
            - { name: NODE_ENV, value: production }
          volumeMounts:
            - name: config
              mountPath: /app/data/config/app-custom-config.json
              subPath: app-custom-config.json
              readOnly: true
          readinessProbe:
            httpGet: { path: /.well-known/openid-configuration, port: 9000 }
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /.well-known/openid-configuration, port: 9000 }
            periodSeconds: 30
          resources:
            requests: { cpu: 50m, memory: 128Mi }
            limits: { memory: 256Mi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: [ALL] }
      volumes:
        - name: config
          configMap: { name: oidc-config }
---
apiVersion: v1
kind: Service
metadata:
  name: oidc
spec:
  selector: { app: oidc }
  ports:
    - port: 80
      targetPort: 9000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oidc
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
spec:
  ingressClassName: traefik
  tls:
    - hosts: [oidc.example.com]
      secretName: oidc-tls
  rules:
    - host: oidc.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: { name: oidc, port: { number: 80 } }
```

Notes:

- Both replicas share the storage adapter's backing store (a database or Redis the host's adapter talks to); see [More than one instance](#more-than-one-instance) for what stays per pod.
- Probes reach the pod over plain HTTP on the pod IP. Discovery is allowed over plain HTTP for exactly this reason; every other route requires the ingress's `X-Forwarded-Proto: https`.
- Keep the Secret in a sealed or external secret store (Sealed Secrets, External Secrets, SOPS) rather than in Git.
- Rolling a new image is safe: tokens, grants and sessions live in the shared store, and every pod signs with the same keys.

## Releases

Versions follow semantic versioning and are cut with the `/semver` skill: an annotated `vX.Y.Z` tag on master. Between releases the working version is `git describe` (`vX.Y.Z-N-g<sha>`). Pin hosts and images to a released version — `1.2.0` above — not to a branch.
