# simple-idp

`github.com/tpaulus/simple-idp` is a tiny OIDC provider for homelab services that already trust browser or device client certificates verified by Traefik.

It is intentionally narrow:

- authorization code flow only
- static users and static confidential clients
- client certificate identity only on `/authorize`
- discovery, JWKS, `/token`, and `/userinfo` work for back-channel application traffic without browser mTLS

The target cluster manifests live separately in `github.com/tpaulus/kube-config`.

## Non-goals

This project does not implement passwords, MFA, registration, refresh tokens, dynamic client registration, SAML, LDAP, SCIM, device grants, password grants, or admin UIs.

## Quickstart

1. Generate a client CA and an RSA signing key.
2. Set the required environment variables referenced by `examples/config.yaml`.
3. Run config validation:
   ```sh
   go run ./cmd/simple-idp --config ./examples/config.yaml --validate-config
   ```
4. Start the server:
   ```sh
   go run ./cmd/simple-idp --config ./examples/config.yaml --http-addr :8080
   ```
5. Send `/authorize` requests through a trusted reverse proxy that strips spoofable forwarded client-certificate headers and adds Traefik-verified headers.

## Flow

```text
Browser with client cert
  -> Traefik verifies client cert
  -> Traefik forwards verified cert headers
  -> simple-idp maps certificate CN to a static user
  -> simple-idp issues an authorization code
  -> client exchanges the code for ID and access tokens
```

## Endpoints

- `GET /.well-known/openid-configuration`
- `GET /jwks.json`
- `GET /authorize`
- `POST /token`
- `GET /userinfo`
- `POST /userinfo`
- `GET /logout`
- `GET /oidc/v1/end_session`
- `GET /healthz`
- `GET /readyz`

## GitHub Actions and image signing

- `.github/workflows/test.yml` runs tests, race tests, vet, coverage, config validation, and a Docker build.
- `.github/workflows/container.yml` builds and pushes commit images to `ghcr.io/tpaulus/simple-idp`, then signs them with keyless Cosign using GitHub OIDC.
- `.github/workflows/release.yml` publishes release tags, signs release images, and emits checksum metadata.

## HTTPRoute example

See `examples/kubernetes/httproute.yaml` and `KUBERNETES.md` for a split-route example where `/authorize` receives forwarded certificate identity while discovery and token endpoints remain usable for application back channels.
