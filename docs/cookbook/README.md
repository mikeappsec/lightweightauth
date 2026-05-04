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
| [rotate-jwks](rotate-jwks.md) | Rotating JWKS / IdP signing keys with zero-downtime dual-publish → drain → retire. |
| [policy-shadow-mode](policy-shadow-mode.md) | Testing a policy change with shadow mode, canary evaluation, and decision diffing. |
| [cache-invalidation](cache-invalidation.md) | Manually invalidating cached decisions and introspection results. |
| [valkey-outage-drill](valkey-outage-drill.md) | Controlled Valkey outage drill — what breaks, what degrades, how to recover. |
| [apikey-static-backend](apikey-static-backend.md) | Static API key auth with argon2id hashing, per-tenant isolation, and zero-downtime key rotation. |
| [header-stamping-identity-forwarding](header-stamping-identity-forwarding.md) | Strip raw credentials, inject identity headers, and mint short-lived internal JWTs for upstream trust. |
| [mtls-spiffe-mesh](mtls-spiffe-mesh.md) | mTLS + SPIFFE identity extraction via direct TLS or Envoy XFCC, with CEL-based workload policy. |
| [oauth2-introspection-caching](oauth2-introspection-caching.md) | Validate opaque tokens via RFC 7662 introspection with three-tier LRU caching and singleflight dedup. |
| [ratelimit-tenant-isolation](ratelimit-tenant-isolation.md) | Per-tenant token-bucket rate limiting with SLA-tier overrides and optional cluster-wide Valkey coordination. |
| [revocation-immediate-logout](revocation-immediate-logout.md) | Real-time credential deny-list for instant logout, compromise response, and compliance revocation. |
| [cel-expression-authz](cel-expression-authz.md) | CEL expression-based authorization for path/method/claim rules without a full policy engine. |
| [composite-authz-patterns](composite-authz-patterns.md) | Combine authorizers with anyOf/allOf patterns: cheap RBAC fast-path before expensive ReBAC calls. |
| [spicedb-rebac-authorization](spicedb-rebac-authorization.md) | Zanzibar-style fine-grained permissions via SpiceDB `CheckPermission` with template-based resource resolution. |
| [federation-multi-cluster-sync](federation-multi-cluster-sync.md) | Replicate AuthConfig and revocations across clusters via HMAC-signed gRPC with hub-spoke or mesh topology. |
| [wasm-sandboxed-plugins](wasm-sandboxed-plugins.md) | Write custom identifiers/authorizers/mutators in Rust/TinyGo compiled to WASM with resource budgets. |
| [dpop-sender-binding](dpop-sender-binding.md) | RFC 9449 DPoP sender-constrained tokens to prevent replay and theft from public clients. |

Every recipe ends with a teardown stanza so you can iterate without
piling up Helm releases. Open an issue if a recipe drifts from the
chart or controller surface — these are first-class artefacts, not
documentation.
