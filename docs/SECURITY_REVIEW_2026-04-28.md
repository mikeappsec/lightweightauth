# LightweightAuth Security Review — 2026-04-28

## Executive summary

This review covered the local `lightweightauth` repository and sibling repos `lightweightauth-proxy`, `lightweightauth-idp`, `lightweightauth-ebpf`, and `lightweightauth-plugins`. The focus was bug-bounty-style assessment of authentication, authorization, transport trust, deployment defaults, and secret handling.

No critical remote-code-execution issue was identified in the reviewed code. The highest-risk issues are authorization-bypass classes caused by trusting forwarded mTLS certificate headers and by incomplete HMAC request canonicalization. Several medium-risk hardening gaps also exist around unauthenticated control-plane endpoints, OAuth redirect handling, default deployment posture, and plugin transport security.

## Scope and validation

### Repositories reviewed

- `lightweightauth` — core daemon, HTTP/native gRPC/Envoy ext_authz servers, built-in identifiers/authorizers/mutators, Helm/Docker/deployment artifacts.
- `lightweightauth-proxy` — Mode B reverse proxy.
- `lightweightauth-idp` — minimal OIDC issuer stub.
- `lightweightauth-plugins` — sample plugin server and HSJWT plugin.
- `lightweightauth-ebpf` — README-only/stub at time of review.

### Validation performed

- Static review of auth modules, server adapters, proxy request translation, plugin transport, Helm chart, Dockerfile, examples, and CI workflow.
- Grep sweeps for insecure transport, forwarded headers, secret material, body parsing, HTTP server timeouts, gRPC reflection, and Kubernetes hardening controls.
- Test execution:
  - `lightweightauth`: `go test ./...` — passed.
  - `lightweightauth-idp`: `go test ./...` — passed.
  - `lightweightauth-proxy`: `go test ./...` — blocked because `go.mod` requires updates; no code changes were made.
  - `lightweightauth-plugins/go`: `go test ./...` — blocked because `go.mod` requires updates; no code changes were made.

## Severity summary

| Severity | Count | Findings |
| --- | ---: | --- |
| Critical | 0 | None identified. |
| High | 4 | Forged XFCC mTLS identity; incomplete HMAC canonicalization/body coverage; insecure gRPC plugin transport; unauthenticated control-plane service exposure. |
| Medium | 4 | OAuth open redirect; unbounded/timeoutless request paths; Helm defaults lack network isolation and pod hardening; CI/package permissions broader than necessary. |
| Low | 3 | Dev plaintext keys/secrets in examples; IDP discovery advertises unimplemented/weak methods; error/audit messages may expose internal policy details. |

## Findings

### HIGH-01: XFCC-based mTLS identity can be spoofed when the service is reachable by untrusted callers

**Affected code**

- `pkg/identity/mtls/mtls.go`
- `internal/server/http.go`
- `internal/server/grpc.go`
- `lightweightauth-proxy/cmd/lwauth-proxy/main.go`

**Evidence**

The `mtls` identifier accepts `X-Forwarded-Client-Cert` when `Request.PeerCerts` is empty. The parsed certificate is treated as identity material. `trustedIssuers` is optional and, when present, only checks `cert.Issuer.String()` against configured strings. It does not verify that the supplied certificate chains to a trusted root. The core HTTP JSON API and proxy path allow request headers to reach modules, so any client that can reach a `mtls`-configured auth surface can provide its own XFCC header unless an upstream proxy strips or overwrites it.

**Impact**

An attacker who can directly reach the HTTP/native/proxy surface or an Envoy path that preserves inbound XFCC can forge service identity. If policies allow based on SPIFFE URI/CN/issuer claims, this becomes an authentication bypass. The risk remains even with `trustedIssuers` if the attacker can create a self-signed certificate whose issuer DN string matches the allow-list.

**Reproduction/validation notes**

1. Configure `mtls` with no `trustedIssuers`, or with a DN string the attacker can copy.
2. Send a request containing an XFCC `Cert="<url-encoded PEM>"` header for a locally generated certificate with the desired SPIFFE URI/CN.
3. The module parses the certificate and surfaces the subject as identity without validating chain trust.

**Remediation**

- Treat XFCC as trusted only when it is injected by a trusted proxy hop. Add an explicit config flag such as `trustForwardedClientCert: true` that defaults to false.
- Strip `X-Forwarded-Client-Cert` at direct HTTP/proxy ingress unless a trusted-front-proxy mode is enabled.
- When accepting XFCC, validate `Hash`/certificate chain against configured CA roots, or require Envoy `include_peer_certificate` with authenticated ext_authz-only connectivity.
- Document required Envoy/Istio settings: sanitize inbound XFCC, set `forward_client_cert_details`, and restrict direct access to `lwauth`.

### HIGH-02: HMAC signatures do not bind query string, host, or Mode B request body

**Affected code**

- `pkg/identity/hmac/hmac.go`
- `lightweightauth-proxy/cmd/lwauth-proxy/main.go`
- `internal/server/http.go`

**Evidence**

The default HMAC canonicalizer signs only `method`, `path`, `date`, and `sha256(body)`. It omits host, scheme, query string, and selected headers. In the proxy (`Mode B`), `requestFromHTTP` does not read or populate `module.Request.Body`, so the canonicalized body hash is the empty-body hash for all proxied requests. The core HTTP JSON API also does not expose a `body` field in `authorizeRequest` despite `module.Request` supporting it.

**Impact**

If operators use the HMAC identifier to authorize request semantics, an attacker with a valid signature for one request path may replay the signature across different query parameters or hosts. In Mode B, the attacker can also alter the forwarded HTTP body without invalidating the HMAC check because the proxy authorization decision signs an empty body rather than the actual body.

**Example attack scenario**

A signed request for `GET /transfer?id=123&amount=10` can be replayed as `GET /transfer?id=123&amount=1000` if the policy or upstream treats the query as security-relevant but the HMAC canonicalizer signs only `/transfer`.

**Remediation**

- Canonicalize and sign at least method, scheme, host, path, normalized query, selected signed headers, and body digest.
- Require an explicit `X-Lwauth-Content-SHA256`/`Digest` header for streaming proxy paths rather than buffering arbitrary bodies.
- In Mode B, either buffer within a strict size limit and restore the body for upstream, or reject HMAC configs that require body binding until digest-header support exists.
- Add tests for query tampering, host tampering, and body tampering through the proxy.

### HIGH-03: gRPC plugin transport is unauthenticated and unencrypted

**Affected code**

- `pkg/plugin/grpc/client.go`
- `lightweightauth-plugins/go/cmd/sample-grpc-plugin/main.go`

**Evidence**

The plugin client dials all plugin addresses with `insecure.NewCredentials()`. The sample plugin uses `grpc.NewServer()` without TLS or client authentication. Documentation notes mTLS is deferred and suggests localhost or Unix sockets as the intended topology.

**Impact**

When plugins are used over TCP outside a tightly isolated localhost/pod boundary, a network attacker can observe requests, tamper with identity/authorization plugin responses, or impersonate a plugin. Since plugins can provide identities, authorizer decisions, and mutator headers, compromise of this channel can directly become an auth bypass or privilege escalation.

**Remediation**

- Prefer Unix domain sockets by default and reject non-loopback TCP unless `allowInsecureTCP: true` is explicitly set.
- Add mTLS support for plugin client/server with server identity pinning and optional client cert authentication.
- Add per-plugin allow-lists for expected service names/SANs.
- Update examples to make insecure TCP visibly dev-only.

### HIGH-04: Core HTTP and gRPC control-plane surfaces are exposed without built-in transport authentication

**Affected code**

- `pkg/lwauthd/lwauthd.go`
- `internal/server/http.go`
- `internal/server/native.go`
- `internal/server/grpc.go`
- `deploy/helm/lightweightauth/values.yaml`

**Evidence**

`lwauthd.Run` starts HTTP on `:8080` and gRPC on `:9001` by default. The gRPC server registers Envoy ext_authz, native Auth, health, and reflection with no TLS or client authentication. The HTTP handler exposes `/v1/authorize`, `/healthz`, `/readyz`, `/metrics`, and module-mounted OAuth routes. Helm publishes both HTTP and gRPC ports via a ClusterIP service and disables NetworkPolicy by default.

**Impact**

If the service is reachable by untrusted tenants or pods, attackers can enumerate authorization behavior through `/v1/authorize`, scrape metrics, access gRPC reflection, and exercise native authorization APIs directly. This is most dangerous in multi-tenant clusters or when the ClusterIP/service is accidentally exposed beyond the mesh.

**Remediation**

- Make production mode require one of: mTLS, mesh-authenticated ext_authz-only ingress, or explicit `--allow-unauthenticated-control-plane`.
- Allow disabling HTTP `/v1/authorize`, `/metrics`, and gRPC reflection independently.
- Add server-side TLS/mTLS options for both HTTP and gRPC listeners.
- Enable a restrictive NetworkPolicy by default in Helm, or provide a `productionProfile.enabled` mode that does so.

### MEDIUM-01: OAuth2 `rd` parameter enables open redirects after login

**Affected code**

- `pkg/identity/oauth2/flow.go`

**Evidence**

`handleStart` stores `rd` directly from the query parameter, and `handleCallback` redirects to `flow.RD` after a successful OAuth callback. There is no validation that `rd` is a relative path or belongs to an allow-listed host.

**Impact**

Attackers can initiate login with `rd=https://attacker.example/...` and use the legitimate authentication flow as a trusted open redirect. This can support phishing and token-confusion attacks. Session cookies are scoped to the LightweightAuth domain, so direct cookie exfiltration is not the expected impact.

**Remediation**

- Accept only relative paths by default.
- If absolute redirects are required, enforce an explicit `allowedRedirectHosts` allow-list.
- Normalize paths and reject scheme-relative URLs such as `//evil.example`.

### MEDIUM-02: Several HTTP paths lack request-size limits and/or outbound timeouts

**Affected code**

- `pkg/lwauthd/lwauthd.go`
- `internal/server/http.go`
- `pkg/identity/oauth2/device.go`
- `lightweightauth-proxy/cmd/lwauth-proxy/main.go`

**Evidence**

The proxy and idp set `ReadHeaderTimeout`, but core `lwauthd` constructs `http.Server` without `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or `MaxHeaderBytes`. `/v1/authorize` decodes JSON directly from `r.Body` without `http.MaxBytesReader`. Device OAuth uses `http.DefaultClient.Do` and `io.ReadAll(resp.Body)` without a timeout-bound client or response-size limit.

**Impact**

Attackers who can reach HTTP endpoints may consume file descriptors, memory, goroutines, or upstream connections via slowloris, oversized JSON, or oversized IdP responses. This is primarily a denial-of-service risk.

**Remediation**

- Add configurable server timeouts and `MaxHeaderBytes` in `lwauthd.Run`.
- Wrap JSON request bodies with `http.MaxBytesReader`.
- Use an injected `http.Client` with timeout for OAuth device/token calls.
- Limit IdP response bodies with `io.LimitReader` before `ReadAll`/decode.

### MEDIUM-03: Helm deployment defaults are not hardened for production

**Affected code**

- `deploy/helm/lightweightauth/values.yaml`
- `deploy/helm/lightweightauth/templates/deployment.yaml`
- `deploy/helm/lightweightauth/templates/networking.yaml`
- `deploy/helm/lightweightauth/templates/rbac.yaml`

**Evidence**

NetworkPolicy is disabled by default. The pod template has no pod/container `securityContext` settings such as `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, dropped Linux capabilities, or seccomp profile. RBAC is a ClusterRole/ClusterRoleBinding when controller mode is enabled, even if a namespace-scoped Role would satisfy a single-namespace watch.

**Impact**

Default installs have broader network reachability and weaker pod isolation than necessary. A container escape or compromised workload in the cluster has fewer Kubernetes/network barriers before reaching the auth service. Controller permissions are cluster-scoped by default for custom resources.

**Remediation**

- Add a hardened values profile that enables NetworkPolicy and pod/container securityContext.
- Consider namespace-scoped Role/RoleBinding when `controller.watchNamespace` is set and cluster-wide watch is not needed.
- Add chart tests or policy examples for restricted Pod Security Admission.

### MEDIUM-04: CI workflow grants package write and OIDC token permissions globally

**Affected code**

- `.github/workflows/build.yaml`

**Evidence**

The workflow-level `permissions` block grants `packages: write` and `id-token: write` to all jobs, including test jobs that do not need publishing or OIDC. The build job conditionally avoids pushing on pull requests, but least privilege is still not applied at job scope.

**Impact**

If a workflow step or dependency in a non-publishing job is compromised, the job starts with broader token privileges than required. This increases supply-chain blast radius.

**Remediation**

- Move elevated permissions to the build/publish job only.
- Set default workflow permissions to `contents: read`.
- Grant `packages: write` only when pushing images, and `id-token: write` only if provenance/signing requires it.

### LOW-01: Dev examples contain plaintext demo keys and static secrets

**Affected files**

- `examples/config.yaml`
- `examples/dev-local.yaml`
- `examples/dev-oauth2.yaml`
- `lightweightauth-plugins/go/cmd/lwauth-extra/dev.yaml`
- `lightweightauth-plugins/go/cmd/mint/main.go`
- `bin/req-admin.json`

**Evidence**

Multiple example files include static API keys, HSJWT secrets, and OAuth cookie demo secrets. Most are marked as dev/test-only, but some generated request samples also contain usable demo credentials.

**Impact**

Low direct risk if examples remain non-production. The common failure mode is operators copying demo AuthConfigs into staging/production.

**Remediation**

- Keep demo values clearly prefixed with `DEMO_DO_NOT_USE`.
- Prefer environment placeholders in docs and generated request samples.
- Add a startup warning when plaintext `apikey.static` or known demo secrets are loaded outside an explicit dev mode.

### LOW-02: IDP discovery advertises endpoints/methods that are not implemented or production-ready

**Affected code**

- `lightweightauth-idp/cmd/lwauth-idp/main.go`

**Evidence**

The minimal IDP discovery document advertises token/userinfo/device/introspection-style capabilities and `token_endpoint_auth_methods_supported` includes `none`, while the endpoints return `501 not_implemented`.

**Impact**

This can confuse integrators and automated clients. If deployed as a real IdP by mistake, it creates insecure expectations around public/no-auth clients and incomplete OAuth flows.

**Remediation**

- In v0, advertise only endpoints that are implemented, or add a `--dev-discovery` flag for placeholder discovery.
- Mark `none` as dev-only and remove it from production discovery unless public-client policy is implemented.

### LOW-03: Error responses and audit logs may expose internal policy details

**Affected code**

- `internal/pipeline/engine.go`
- `internal/server/http.go`
- `internal/server/grpc.go`
- `lightweightauth-proxy/cmd/lwauth-proxy/main.go`

**Evidence**

Deny reasons and upstream errors are returned to clients in HTTP bodies, Envoy denied responses, `X-Lwauth-Reason`, and proxy 503 bodies. Audit events also record full deny reasons.

**Impact**

Attackers can learn policy names, module types, upstream status codes, and some configuration details. This is useful for enumeration but is not by itself an auth bypass.

**Remediation**

- Return generic client-facing deny messages by default.
- Keep detailed errors in audit/structured logs gated by log level or internal sinks.
- Avoid adding raw upstream error bodies to external responses.

## Positive observations

- JWT verification uses JWKS-backed signature validation with `exp`/`nbf`/`iat` enforcement and optional issuer/audience pinning.
- API-key hashed storage uses Argon2id and constant-time digest comparison.
- Session cookies use AES-GCM, `HttpOnly` defaults true, `Secure` defaults true, and cookie size is capped.
- DPoP implementation rejects symmetric/none algorithms, checks `htm`/`htu`/`iat`/`jti`, and validates `ath` binding when bearer tokens are present.
- Decision-cache keys are hashed and upstream errors are not cached.
- Main repository test suite passes, including module-level security-adjacent tests.

## Recommended remediation order

1. Fix `mtls` XFCC trust boundaries and add chain/CA validation or explicit trusted-proxy-only mode.
2. Replace HMAC canonicalization with a signed-header/query/body-digest model and add proxy body/digest coverage tests.
3. Add mTLS or explicit local-only enforcement for gRPC plugins.
4. Add production listener hardening: TLS/mTLS options, reflection toggle, HTTP API/metrics toggles, request-size limits, and timeouts.
5. Add OAuth redirect validation for `rd`.
6. Ship a hardened Helm profile with NetworkPolicy and restricted pod security defaults.
7. Narrow GitHub Actions permissions by job.
8. Clean up demo secrets and add warnings for plaintext/static credential backends.

## Notes

This report is based on local source review and focused validation, not a live black-box assessment against a deployed environment. Severity should be adjusted upward if any of the affected services are exposed outside a trusted mesh/VPC, and downward if compensating controls already enforce network isolation, header sanitization, mTLS, and strict deployment policy.