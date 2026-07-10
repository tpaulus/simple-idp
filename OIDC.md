# OIDC behavior

## Supported subset

- authorization code flow
- confidential clients
- `client_secret_basic`
- optional `client_secret_post`
- optional PKCE S256
- OIDC discovery
- JWKS
- UserInfo
- logout compatibility endpoint with safe redirects only

Unsupported grants and response types are rejected.

## Discovery metadata

Discovery is generated from config and advertises:

- issuer
- authorization, token, userinfo, JWKS, and logout endpoints
- `response_types_supported: ["code"]`
- `grant_types_supported: ["authorization_code"]`
- `id_token_signing_alg_values_supported: ["RS256"]`

## Tokens

ID tokens contain `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `email`, `email_verified`, `name`, `preferred_username`, optional `nonce`, and optional static `groups`.

Access tokens are JWTs intended for `/userinfo` validation.

## UserInfo

`/userinfo` requires a bearer access token. It returns claims consistent with granted scopes:

- always: `sub`
- `email`: `email`, `email_verified`
- `profile`: `name`, `preferred_username`, optional `groups`
