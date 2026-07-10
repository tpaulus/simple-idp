# Kubernetes examples

The example manifests live in `examples/kubernetes/` and are intentionally standalone. They do not modify `tpaulus/kube-config`.

Included examples:

- `configmap.yaml`
- `deployment.yaml`
- `service.yaml`
- `httproute.yaml`
- `networkpolicy.yaml`

## Routing guidance

Prefer route-specific behavior so `/authorize` receives forwarded client-certificate identity while discovery, token, JWKS, logout, and probes remain usable for application back-channel traffic.

If the installed Traefik Gateway API extension cannot attach certificate-forwarding middleware only to `/authorize`, use a safe fallback that keeps `simple-idp` off the public network and continues stripping spoofable forwarded identity headers before Traefik adds its own.
