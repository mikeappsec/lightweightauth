# FIPS 140-3 build mode (K-CRYPTO-2)

Operators in regulated environments (FedRAMP High, DoD IL5, PCI-DSS,
HIPAA-with-cryptographic-controls) need an artifact whose cryptographic
module has been validated against
[FIPS 140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program).
v1.1 ships a separately-tagged FIPS image and the supporting build
plumbing.

The runtime code path is **identical** between the stock and FIPS
builds — `pkg/identity/jwt`, `pkg/identity/hmac`, `pkg/identity/dpop`,
`pkg/clientauth`, all TLS terminations — every primitive routes through
the standard library. Switching the build mode flips the standard
library's crypto backend; nothing in lwauth needs to know.

## Build modes

| Mode                    | Toolchain selector             | When to use                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------|
| Stock                   | (default)                     | Most deployments. No cryptographic-module validation requirements.            |
| FIPS 140-3 (Go ≥ 1.24)  | `GOFIPS140=v1.0.0`            | Recommended for new deployments. Pure-Go in-tree FIPS module, no CGO.        |
| BoringCrypto (legacy)   | `GOEXPERIMENT=boringcrypto`   | Only when an existing certificate references the older Boring path.          |

`make fips` defaults to `GOFIPS140`. Override with
`make fips GOFIPS140_VER=v1.1.0` once a later certificate revision
ships, or invoke `go build` directly if your release pipeline manages
the toolchain selector itself.

## Building

```bash
# Local artifacts (binaries land under bin/fips/)
make fips
make fips-verify         # asserts buildinfo.FIPSEnabled() at runtime

# Run the full test suite under the FIPS module so a primitive that
# only differs in FIPS mode (e.g. an RSA key < 2048 bits, MD5 fallback,
# legacy KDF parameters) surfaces as a test failure.
make fips-test

# Container image with the `-fips` tag suffix.
make docker-fips IMAGE=ghcr.io/acme/lwauth TAG=v1.1.0
```

CI mirrors these targets in [`.github/workflows/build.yaml`](../../.github/workflows/build.yaml):
the `fips-test` job builds + tests the FIPS variant on every push, and
`build-fips` publishes `ghcr.io/<owner>/lightweightauth:<tag>-fips`
alongside the stock image.

## Verifying a deployment

Three independent checks; an operator-trust pipeline should assert at
least two.

### 1. Image-policy admission webhook

`Dockerfile.fips` stamps two image-level signals:

- **Tag suffix** — `lightweightauth:<TAG>-fips`. A regex match in
  Kyverno / OPA-Gatekeeper / Sigstore policy pins it.
- **OCI label** — `org.lightweightauth.fips140=enabled` and
  `org.lightweightauth.fips140.module=GOFIPS140`. Cluster admission
  controllers can match on the label, which survives even if a
  downstream pipeline strips or rewrites the tag.

A stock image that accidentally lands in a regulated namespace fails
both checks.

### 2. `lwauth_fips_enabled` Prometheus gauge

The metrics surface always exposes:

```text
# HELP lwauth_fips_enabled 1 if the running binary uses a FIPS 140-3
# validated cryptographic module (GOFIPS140 or
# GOEXPERIMENT=boringcrypto build), 0 otherwise.
# TYPE lwauth_fips_enabled gauge
lwauth_fips_enabled 1
lwauth_build_info{commit="abc1234",fips="true",go_version="go1.26.2",version="v1.1.0"} 1
```

Alert rule:

```yaml
- alert: LwauthFipsBuildMissing
  expr:  max(lwauth_fips_enabled{namespace=~"regulated-.+"}) == 0
  for:   5m
  labels: { severity: page }
  annotations:
    summary: lwauth in {{ $labels.namespace }} is not running a FIPS build.
```

### 3. Runtime self-report

The binary itself prints a deterministic single-line build banner:

```bash
$ docker run --rm ghcr.io/acme/lwauth:v1.1.0-fips --print-build-info
version=v1.1.0 commit=abc1234 go_version=go1.26.2 fips_enabled=true
```

The Dockerfile's build stage runs the same probe and **fails the
image build** if the produced binary doesn't self-report
`fips_enabled=true` — so a toolchain regression that silently strips
FIPS support never reaches the registry.

## What "FIPS-validated" means in practice

Switching the build flips the backend for every primitive lwauth
touches via the standard library. The table below names the call
sites; nothing in lwauth re-implements crypto, so this is the full
list.

| Primitive                       | Used by                                                                 | Stock backend         | FIPS backend                                                |
|---------------------------------|-------------------------------------------------------------------------|-----------------------|-------------------------------------------------------------|
| TLS 1.2 / 1.3                   | HTTP & gRPC listeners; outbound JWKS / introspection / plugin clients   | Go stdlib             | Same Go stdlib, restricted to the FIPS-approved cipher list |
| RSA-PKCS1 / RSA-PSS / RSA-OAEP  | JWT RS256 / PS256 verify; mTLS & client-cert paths                       | Go stdlib             | FIPS module; rejects keys < 2048 bits                       |
| ECDSA P-256 / P-384             | JWT ES256 / ES384 verify; DPoP                                          | Go stdlib             | FIPS module                                                 |
| HMAC-SHA-256 / 384 / 512        | JWT HS256/384/512; pkg/identity/hmac; F-PLUGIN-2 plugin signatures      | Go stdlib             | FIPS module                                                 |
| SHA-256 / 384 / 512             | Token hashing for cache keys; introspection error-cache; HMAC payloads  | Go stdlib             | FIPS module                                                 |
| AES-GCM                         | Session cookies (when configured)                                        | Go stdlib             | FIPS module                                                 |
| crypto/rand                     | Nonce / state / PKCE-verifier generation                                 | OS RNG                | FIPS-approved DRBG (CTR_DRBG-AES-256)                       |

Primitives **not** approved under FIPS 140-3 (e.g. Ed25519, X25519
key agreement, ChaCha20-Poly1305) are unavailable in FIPS mode. lwauth
v1.1 doesn't currently use any of them; adding one would fail
`make fips-test` before a release ships.

### Common pitfalls the FIPS test suite catches

- A configuration that pins a non-FIPS TLS cipher suite (e.g.
  TLS_CHACHA20_POLY1305_SHA256). The TLS handshake fails at startup.
- An issuer whose JWKS publishes an RSA-1024 key. JWT verification
  returns `module.ErrInvalidCredential`; the cache stores the negative
  result so a flood of forged short-RSA tokens doesn't fan out to
  JWKS refetches.
- A plugin that ships an HMAC secret shorter than 16 bytes
  (F-PLUGIN-2 already requires this; under FIPS it is doubly enforced
  by the underlying `hmac.New`).

## Operational notes

- **Performance.** The FIPS module is pure Go on Go 1.24+ and within
  ~3 % of the stock backend in our soak harness
  (`make soak SOAK_DURATION=30m`). Earlier BoringCrypto numbers
  (~10–20 % regression) do not apply.
- **CGO.** `GOFIPS140` does **not** require CGO. The stock and FIPS
  images both build with `CGO_ENABLED=0`, which keeps the runtime
  image identical to the stock alpine layer (no glibc, no
  libcrypto.so).
- **Provenance.** The CI pipeline builds the FIPS image with
  `provenance: true` and `sbom: true`, so consumers can verify the
  exact toolchain + dependency set that produced the binary.
- **Validation lifecycle.** A FIPS *certificate* is a property of the
  module + Go release combination, not of lwauth. Track the
  [Go FIPS module status](https://go.dev/doc/security/fips140) and
  bump `GOFIPS140_VER` (and the toolchain pin in
  `.github/workflows/build.yaml`) when a new certificate ships.

## References

- Source: [pkg/buildinfo/buildinfo.go](../../pkg/buildinfo/buildinfo.go)
- Image: [Dockerfile.fips](../../Dockerfile.fips)
- Build targets: [Makefile](../../Makefile) (`fips`, `fips-test`, `fips-verify`, `docker-fips`)
- CI: [.github/workflows/build.yaml](../../.github/workflows/build.yaml)
  (`fips-test`, `build-fips` jobs)
- Roadmap: [DESIGN.md §7 Tier A5](../DESIGN.md), [v1.0-review.md §10 Tier A](../security/v1.0-review.md)
