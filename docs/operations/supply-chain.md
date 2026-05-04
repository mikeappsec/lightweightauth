# Supply-Chain Trust & Air-Gap Deployment

This document covers artifact verification and air-gap installation for
LightweightAuth releases.

## Release artifacts

Every tagged release (`v*`) produces the following artifacts via GitHub
Actions:

| Artifact | Location | Integrity |
|----------|----------|-----------|
| Go binaries (linux/amd64, linux/arm64, darwin/arm64) | GitHub Release assets | SHA-256 in `checksums.txt` |
| `checksums.txt` signature | `checksums.txt.sig` + `checksums.txt.pem` | Cosign keyless (Sigstore OIDC) |
| SLSA provenance | `multiple.intoto.jsonl` (attached to Release) | SLSA level 3 via `slsa-github-generator` |
| Container images (stock + FIPS) | `ghcr.io/mikeappsec/lightweightauth` | Docker provenance + SBOM embedded |
| FIPS image base (hardened) | `dhi.io/golang:1.26.2`, `dhi.io/alpine:3.22.4` | Authenticated pull; minimal-CVE hardened images |
| Helm chart (OCI) | `ghcr.io/mikeappsec/charts/lightweightauth` | Cosign keyless signature |
| Per-binary SBOM | `lightweightauth_<ver>.sbom.json` (SPDX) | Attached to Release |

## Verifying artifacts

### Verify binary checksums

```bash
# Download the release archive + checksums + signature
curl -LO https://github.com/mikeappsec/lightweightauth/releases/download/v1.2.0/checksums.txt
curl -LO https://github.com/mikeappsec/lightweightauth/releases/download/v1.2.0/checksums.txt.sig
curl -LO https://github.com/mikeappsec/lightweightauth/releases/download/v1.2.0/checksums.txt.pem

# Verify Cosign signature (keyless — verifies against Sigstore transparency log)
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/mikeappsec/lightweightauth/"

# Verify individual archive checksum
sha256sum -c checksums.txt --ignore-missing
```

### Verify SLSA provenance

```bash
slsa-verifier verify-artifact lightweightauth_1.2.0_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/mikeappsec/lightweightauth \
  --source-tag v1.2.0
```

### Verify container image

```bash
# Verify image signature
cosign verify ghcr.io/mikeappsec/lightweightauth:1.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/mikeappsec/lightweightauth/"

# Verify Helm OCI chart
cosign verify ghcr.io/mikeappsec/charts/lightweightauth:1.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/mikeappsec/lightweightauth/"
```

## Air-gap installation

For environments without internet access, mirror the required artifacts
to an internal registry.

### 1. Mirror container images

```bash
VERSION=1.2.0

# Resolve tags to immutable digests first (prevents tag-swap attacks
# between verification and pull).
DIGEST=$(crane digest ghcr.io/mikeappsec/lightweightauth:${VERSION})
DIGEST_FIPS=$(crane digest ghcr.io/mikeappsec/lightweightauth:${VERSION}-fips)

# Pull by digest from public registry (on a connected host)
crane pull ghcr.io/mikeappsec/lightweightauth@${DIGEST} lwauth-${VERSION}.tar
crane pull ghcr.io/mikeappsec/lightweightauth@${DIGEST_FIPS} lwauth-${VERSION}-fips.tar

# Transfer tarballs to air-gapped network, then push
crane push lwauth-${VERSION}.tar registry.internal/lwauth/lightweightauth:${VERSION}
crane push lwauth-${VERSION}-fips.tar registry.internal/lwauth/lightweightauth:${VERSION}-fips
```

### 2. Mirror Helm chart

```bash
# Pull chart as OCI
helm pull oci://ghcr.io/mikeappsec/charts/lightweightauth --version ${VERSION}

# Push to internal registry
helm push lightweightauth-${VERSION}.tgz oci://registry.internal/charts
```

### 3. Install from internal registry

```bash
helm install lwauth oci://registry.internal/charts/lightweightauth \
  --version ${VERSION} \
  --set image.repository=registry.internal/lwauth/lightweightauth \
  --set image.tag=${VERSION}
```

### 4. Transfer binaries

Copy the release archive and `checksums.txt` to the air-gapped host.
Verify checksums offline (the SHA-256 check doesn't require internet):

```bash
sha256sum -c checksums.txt --ignore-missing
tar xzf lightweightauth_${VERSION}_linux_amd64.tar.gz
install -m 0755 lwauth lwauthctl /usr/local/bin/
```

## Admission policy integration

For clusters that enforce image provenance at admission time:

- **Kyverno**: match on `ghcr.io/mikeappsec/lightweightauth` and
  require `cosign verify-image` with the Sigstore OIDC issuer.
- **Sigstore policy-controller**: create a `ClusterImagePolicy` with
  the `keyless` authority and the workflow identity pattern.
- **FIPS images**: additionally match on the
  `org.lightweightauth.fips140=enabled` OCI label or the `-fips` tag
  suffix for namespace-level enforcement.

See [fips.md](fips.md) for FIPS-specific admission webhook examples.

## Hardened base images (dhi.io)

The FIPS image (`Dockerfile.fips`) uses hardened base images from
`dhi.io` instead of public Docker Hub images. These images have:
- Minimal CVE surface (no shell, no package manager in runtime image)
- FIPS-validated crypto libraries pre-installed
- Regular security patching on a defined SLA

### CI authentication

The `build-fips` job in `.github/workflows/build.yaml` authenticates to
`dhi.io` using encrypted GitHub secrets:

- `DHI_USERNAME` — service account username (pull-only scope)
- `DHI_TOKEN` — API token (pull-only scope, not a personal password)

**Security controls:**
1. The entire `build-fips` job is gated by
   `if: github.event_name != 'pull_request'` — fork PRs never access
   the credentials.
2. `docker/login-action` stores credentials in `~/.docker/config.json`
   which BuildKit reads implicitly — credentials never appear in build
   args, layer history, or workflow logs.
3. The action automatically masks the token value in all log output.

### Local development

Developers without dhi.io access can build locally using the stock
Dockerfile (which uses public `golang:` and `alpine:` images):

```bash
# Stock build (no dhi.io credentials needed)
docker build -t lwauth:dev .

# FIPS build requires dhi.io login:
docker login dhi.io
docker build -f Dockerfile.fips -t lwauth:dev-fips .
```

## Dependabot quarantine (14-day hold)

Automated dependency update PRs from Dependabot are **not merged
immediately**. A companion workflow
([`.github/workflows/dependabot-quarantine.yml`](https://github.com/mikeappsec/lightweightauth/blob/main/.github/workflows/dependabot-quarantine.yml))
enforces a 14-day quarantine window:

1. When Dependabot opens a PR, the workflow labels it `quarantine:14d`.
2. A daily cron job checks all open Dependabot PRs. Once a PR is older
   than 14 days, the workflow approves it and removes the label.
3. Branch protection rules require at least one approval before merge,
   so the quarantine label effectively blocks the PR until the window
   passes.

**Why 14 days?** Most supply-chain compromises (typosquatting,
account takeovers, malicious releases) are detected and yanked within
the first few days of publication. Waiting two weeks dramatically
reduces exposure without sacrificing patch velocity for genuine
security fixes.

**Override for critical CVEs:** If a Dependabot PR addresses a
known-exploited vulnerability (e.g., CISA KEV entry), a maintainer can
manually approve the PR to bypass the quarantine window.
