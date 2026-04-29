# LightweightAuth

A pluggable identification, authorization, and response-mutation pipeline
for HTTP and gRPC. Single binary, embeddable Go library, Envoy `ext_authz`
adapter — pick the deployment shape that fits, share the same modules.

## Where to start

- **New here?** Read the [Quickstart](QUICKSTART.md), then pick a recipe
  from the [Cookbook](cookbook/README.md).
- **Integrating a specific identifier or authorizer?** Open the
  [Module reference](modules/README.md) and jump to the relevant page.
- **Designing a deployment?** Start at [Architecture](ARCHITECTURE.md),
  then [Design](DESIGN.md) for the long-form rationale.
- **Operating it?** [Deployment](DEPLOYMENT.md), the Envoy guide under
  [deployment/envoy.md](deployment/envoy.md), and the FIPS build target
  in [operations/fips.md](operations/fips.md).
- **Reviewing security posture?** The latest pass is
  [security/SECURITY_HARDENING_2026-04-29.md](security/SECURITY_HARDENING_2026-04-29.md);
  the long-form review sits at
  [security/v1.0-review.md](security/v1.0-review.md).

The site you are reading is built from the same Markdown that ships in
the repository under `docs/` — every page has an "Edit this page" link
that points at the source file. See
[docs site build](#docs-site-build) below for how to preview locally.

## Docs site build

The static site is built with [mkdocs-material]. Two `make` targets
cover the common cases:

| Target            | What it does                                                |
| ----------------- | ----------------------------------------------------------- |
| `make docs-serve` | Live-reload preview at <http://127.0.0.1:8000>.             |
| `make docs`       | Strict build into `site/`. Fails on broken links / nav.     |

Both targets resolve their dependencies through `pip install -r
docs/requirements.txt` so a contributor without Python in their dev shell
can still drive the build via `python -m pip` directly:

```bash
python -m pip install -r docs/requirements.txt
python -m mkdocs serve --strict
```

`make docs` runs `mkdocs build --strict`, which is what the release
pipeline runs; if it passes locally, it passes in CI.

[mkdocs-material]: https://squidfunk.github.io/mkdocs-material/
