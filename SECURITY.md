# Security

## Trust model

Traefik proves possession of the client certificate during TLS. `simple-idp` only trusts forwarded certificate headers from configured proxy CIDRs.

Requests that reach `/authorize` directly from untrusted remotes with spoofed forwarded certificate headers are rejected.

## Certificate handling

When the PEM header is present, the service:

- parses the certificate
- validates the chain to the configured client CA
- validates certificate time bounds
- requires client-auth EKU when EKU is present
- extracts the certificate CN
- rejects mismatches between PEM CN and forwarded info CN

## OAuth safeguards

- authorization codes are generated with `crypto/rand`
- only hashes of authorization codes are stored
- codes are one-time use and short-lived
- client secrets use constant-time comparison
- exact redirect URI matching prevents open redirects
- only `authorization_code`, `client_secret_basic`, optional `client_secret_post`, and optional PKCE S256 are supported
- `/userinfo` accepts only signed bearer access tokens issued by this service

## Operational safeguards

- secure headers: `Cache-Control: no-store`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`
- restrictive CSP on static logout pages
- bounded token request body size
- bounded header size via server configuration
- rate limiting on `/authorize` and `/token`
- resolved secrets are redacted from config validation output
