# Configuration

All non-secret configuration is file-based and loaded with `--config`.

Only exact `ENV:NAME` references resolve environment variables. Missing or empty variables are fatal.

## CLI flags

- `--config /etc/simple-idp/config.yaml`
- `--http-addr :8080`
- `--log-format json`
- `--validate-config`

## Core settings

```yaml
issuer: "https://auth.whitestar.systems"
endpoints:
  authorization: "https://auth.whitestar.systems/authorize"
  token: "https://auth.whitestar.systems/token"
  userinfo: "https://auth.whitestar.systems/userinfo"
  jwks: "https://auth.whitestar.systems/jwks.json"
  logout: "https://auth.whitestar.systems/logout"
```

## Trust boundary settings

```yaml
http:
  trustedProxyCIDRs: ["10.42.0.0/16"]
forwardedClientCert:
  pemHeader: "X-Forwarded-Tls-Client-Cert"
  infoHeader: "X-Forwarded-Tls-Client-Cert-Info"
  requirePem: true
  requireInfoCommonName: true
  caPem: "ENV:CLIENT_CA_CRT"
```

`/authorize` only trusts forwarded certificate headers from configured proxy CIDRs.

## OAuth settings

```yaml
oauth:
  authorizationCodeTTL: "60s"
  accessTokenTTL: "10m"
  idTokenTTL: "10m"
  issuerClockSkew: "30s"
  requirePKCES256: false
  allowClientSecretPost: true
  maxOutstandingCodes: 512
```

## Signing keys

Only `RS256` is supported. Exactly one key must be active.

```yaml
signingKeys:
  - keyID: "main-rs256"
    algorithm: "RS256"
    privateKeyPem: "ENV:OIDC_SIGNING_KEY"
    active: true
```

Inactive signing keys stay in JWKS so older tokens can still validate until they expire.

## Static users and clients

Users are keyed by stable subjects and one or more certificate common names. Clients use exact redirect URI and post-logout redirect URI matching.

See `examples/config.yaml` for a complete sample.
