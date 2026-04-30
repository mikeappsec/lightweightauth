# lwauth cookbook

Each recipe in this folder is a runnable, dryrun-tested guide that
takes you from a fresh kind cluster to a working lwauth deployment for
one specific scenario. All scripts use stdlib-only Python or
PowerShell so a clean checkout works without `pip install`.

| Recipe | What it shows |
|---|---|
| [gate-upstream-service](gate-upstream-service.md) | Wire Envoy + lwauth ext_authz in front of a backend; NetworkPolicy enforced by Cilium so direct-to-backend bypasses fail. |
| [oauth2-pkce](oauth2-pkce.md) | Full Authorization Code + PKCE flow against `lwauth-idp`; gateway verifies JWTs minted by the IdP via JWKS. |
| [openfga-on-envoy](openfga-on-envoy.md) | ReBAC with OpenFGA: tuples, model bootstrap, AuthConfig with `composite{anyOf:[rbac, openfga]}`. |
| [istio-grpc-rbac](istio-grpc-rbac.md) | lwauth as the ext_authz provider in an Istio mesh, gating gRPC services with role-based policy. |
| [rotate-hmac](rotate-hmac.md) | Rolling an HMAC shared secret with zero downtime via the multi-secret overlap window. |

Every recipe ends with a teardown stanza so you can iterate without
piling up Helm releases. Open an issue if a recipe drifts from the
chart or controller surface — these are first-class artefacts, not
documentation.
