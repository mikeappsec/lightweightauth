# Envoy + lwauth deployment guide

This page is the operator-facing companion to [DEPLOYMENT.md §2 Topology
2 — Envoy + lwauth sidecar](../DEPLOYMENT.md). The high-level shape lives
there; **what's here is the minimum-safe `ext_authz` config**, and the
*why* behind every non-default field. If you skip this page you will
likely deploy a configuration that silently bypasses HMAC body binding
and accepts spoofed forwarded headers — see [§3 SEC-PROXY-1
parity](#3-sec-proxy-1-parity) for the gory details.

Tested against Envoy **1.37.3**. The `envoy.service.auth.v3` API is
unchanged from 1.18 → 1.37, so the wiring works on any 1.18+ Envoy. The
sample config under [deploy/envoy/sample.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/deploy/envoy/sample.yaml)
is the minimum that boots; the snippets below are the minimum that's
**safe in production**.

## 1. Topology

```
client ─► Envoy ──(ext_authz gRPC :9001)──► lwauth
              └──(if allowed)─────────────► upstream
```

Envoy and `lwauth` typically run in the same Pod (or as separate Pods
behind a Service). The `envoy.filters.http.ext_authz` filter targets
`lwauth:9001`. The same pattern works for Istio's
`AuthorizationPolicy` with `provider:` set to lwauth, and for Gateway
API extension filters — the lwauth side is identical.

## 2. Minimum safe ext_authz config

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      grpc_service:
        envoy_grpc:
          cluster_name: lwauth
        timeout: 0.25s

      # Fail closed if lwauth is unreachable / errors. Default in many
      # filter chains is true — that defeats the entire point of having
      # an auth server.
      failure_mode_allow: false

      # Forward the client cert (PEM, URL-encoded) to lwauth so the
      # mtls identifier and any policy that keys off the cert subject
      # works. No-op if you don't terminate mTLS at Envoy.
      include_peer_certificate: true

      # Let lwauth's mutators (UpstreamHeaders, header-add) re-route
      # the request after auth — without this, route selection is
      # frozen before mutators run.
      clear_route_cache: true

      # ─── BODY BINDING (SEC-PROXY-1 parity, see §3) ───────────────
      with_request_body:
        max_request_bytes: 1048576       # 1 MiB; match --max-auth-body
        allow_partial_message: false     # MUST be false; see §3
        pack_as_bytes: true              # MUST be true;  see §3
```

**Per-route override** if 99% of your traffic is small JSON but one
endpoint accepts large uploads. Bumping the global `max_request_bytes`
to (say) 50 MiB is a DoS multiplier on every other route; per-route
keeps the blast radius small.

```yaml
typed_per_filter_config:
  envoy.filters.http.ext_authz:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
    check_settings:
      with_request_body:
        max_request_bytes: 52428800     # 50 MiB on this route only
        allow_partial_message: false
        pack_as_bytes: true
```

## 3. SEC-PROXY-1 parity

[SEC-PROXY-1](../security/v1.0-review.md#10-outstanding-follow-ups-post-v10)
was a Mode B (`lightweightauth-proxy`) bug that had **three** sub-bugs;
two of them don't exist in Mode A, but **one is a configuration trap
that bites Envoy operators by default**.

| Sub-bug | Mode B (proxy) | Mode A (Envoy) |
|---|---|---|
| Query string dropped before auth | Code bug, fixed | Not affected — Envoy populates `attributes.request.http.path` with the full request URI, which lwauth reads. |
| Engine never sees the request body | Code bug, fixed (bounded buffer + replay) | **Configuration trap** — Envoy doesn't send the body unless you opt in via `with_request_body`, **and** the opt-in has two non-obvious flags that must be set correctly. See below. |
| Verbose deny reasons leak to clients | Code bug, fixed (`publicReason` redaction) | Not affected — Envoy renders the response body, not the engine. The verbose reason flows to the proxy log via the `x-lwauth-reason` response header which operators are expected to strip at the edge (see [§4.4](#44-strip-internal-headers-at-the-edge)). |

### 3.1 `allow_partial_message: false` is mandatory

If `allow_partial_message: true` (the default in some filter chains),
Envoy will buffer up to `max_request_bytes`, send whatever it captured
to lwauth, and **let the request through with a partial body**. That
is exactly the attack-shifting-content-past-the-cap scenario the
proxy fix avoids: an attacker crafts a request whose first
`max_request_bytes` of body sign cleanly under HMAC, then appends
arbitrary tampered tail past the cap.

With `allow_partial_message: false`, Envoy returns **413 Payload Too
Large** to the client when the body exceeds the cap, before lwauth is
even consulted. Fail closed.

### 3.2 `pack_as_bytes: true` is mandatory for HMAC

If `pack_as_bytes: false` (the default), Envoy stuffs the body into the
`CheckRequest.attributes.request.http.body` **string** field when it
parses as valid UTF-8, and `raw_body` (bytes) only when it doesn't.
Mixed encoding paths means HMAC has two cases to handle and one of
them (the string path) silently re-encodes — which can change a single
byte and break the signature. Always `true` for binary-safe binding.

### 3.3 `failure_mode_allow: false` is non-negotiable

If you fail open, an attacker who can DoS lwauth (or just delay it past
your `timeout`) makes every guarded route world-readable. The default
in many filter configs is `true`. Set it `false` and pair it with
generous resource limits / HPA on lwauth, not with fail-open.

## 4. Other Envoy hardening

These are not strictly SEC-PROXY-1 but live in the same operator
checklist; getting any of them wrong causes a comparable bypass.

### 4.1 Forwarded-header trust

Envoy's `use_remote_address`, `xff_num_trusted_hops`, and
`skip_xff_append` settings determine what `X-Forwarded-For` value
reaches lwauth. If a malicious client can prepend XFFs that survive
into lwauth's view of `peerAddr`, **any policy that keys off source
IP is spoofable**. The Mode B equivalent is the `--trust-forward-headers`
flag, which defaults to off.

```yaml
http_connection_manager:
  use_remote_address: true              # actually use the L4 peer
  xff_num_trusted_hops: 1               # trust exactly one hop (your LB)
  skip_xff_append: false
```

### 4.2 Header / stream limits

Cap header counts and stream durations at the listener level so a
slow client can't keep ext_authz buffers pinned indefinitely.

```yaml
http_connection_manager:
  common_http_protocol_options:
    max_headers_count: 100
    max_stream_duration: 5s
  request_headers_timeout: 5s
```

### 4.3 mTLS identifier wiring

If your identifier chain uses the `mtls` module, you need both:

1. `include_peer_certificate: true` on the ext_authz filter (above), so
   the cert reaches lwauth.
2. **lwauth-side anchor** configured — `trustedCAs` / `trustedCAFiles`
   or `trustedIssuers`. As of [SEC-MTLS-1](../security/v1.0-review.md#10-outstanding-follow-ups-post-v10),
   lwauth's `mtls` factory will **fail closed at startup** if
   `trustForwardedClientCert: true` is set without an anchor. See
   [docs/modules/mtls.md](../modules/mtls.md).

### 4.4 Strip internal headers at the edge

lwauth surfaces the verbose deny reason on the `x-lwauth-reason`
response header so operators can correlate denies to logs. **Strip it
at the public edge** — it's the same vocabulary the proxy now redacts:

```yaml
response_headers_to_remove:
  - x-lwauth-reason
  - x-lwauth-decision-id   # if you don't want correlation IDs leaking
```

If you run a public-facing Envoy fronted by a private one (the typical
"two-tier" setup), strip these on the **outer** Envoy and keep them on
the inner one for log joins.

## 5. Production checklist

Operators copying this config into a production cluster should
explicitly verify:

- [ ] `failure_mode_allow: false` on the ext_authz filter.
- [ ] `with_request_body` configured **iff** any identifier or policy
      binds the body (HMAC, body-keyed CEL/OPA). If you don't bind the
      body, leave `with_request_body` unset — it's a per-request memory
      cost.
- [ ] When `with_request_body` is set: `allow_partial_message: false`
      and `pack_as_bytes: true`. Both default-wrong for HMAC.
- [ ] `include_peer_certificate: true` if and only if you use the
      `mtls` identifier; lwauth-side `trustedIssuers` / `trustedCAs`
      configured (SEC-MTLS-1 will fail-closed at startup otherwise).
- [ ] `use_remote_address: true` + `xff_num_trusted_hops` set to the
      actual hop count. Don't accept arbitrary XFF chains.
- [ ] `clear_route_cache: true` if any mutator can change the routing
      decision (`UpstreamHeaders`, host rewrite).
- [ ] `response_headers_to_remove: [x-lwauth-reason]` on the outermost
      Envoy.
- [ ] NetworkPolicy: only Envoy / the mesh may reach `lwauth:9001`.
- [ ] Resource limits set on `lwauth` (CPU-bound on JWT verify).
- [ ] PDB with `maxUnavailable: 1` if `replicaCount >= 2`; HPA on CPU
      plus the custom histogram `lwauth_decision_latency_seconds_bucket`.
- [ ] Image signed with cosign; verify via Kyverno / Sigstore policy.

## 6. References

- Sample boot config: [deploy/envoy/sample.yaml](https://github.com/mikeappsec/lightweightauth/blob/main/deploy/envoy/sample.yaml)
- Topology + Helm wiring: [docs/DEPLOYMENT.md](../DEPLOYMENT.md)
- SEC-PROXY-1 write-up: [docs/security/v1.0-review.md](../security/v1.0-review.md)
- Mode B (proxy) equivalent flags: [lightweightauth-proxy/cmd/lwauth-proxy/main.go](https://github.com/mikeappsec/lightweightauth/blob/main/lightweightauth-proxy/cmd/lwauth-proxy/main.go) — `--max-auth-body`, `--trust-forward-headers`.
- mTLS module + anchor requirement: [docs/modules/mtls.md](../modules/mtls.md)
- Envoy ext_authz reference: <https://www.envoyproxy.io/docs/envoy/v1.37.3/configuration/http/http_filters/ext_authz_filter>
