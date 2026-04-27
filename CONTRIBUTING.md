# Contributing to LightweightAuth

Thanks for your interest! LightweightAuth is in **early M0** state — the public surface is
still moving. Please open an issue to discuss substantive changes before sending a PR.

## Dev loop

```sh
make tidy        # resolve module deps
make build       # compile lwauth + lwauthctl into bin/
make test        # run unit tests
make run         # run lwauth with examples/config.yaml
```

Requires Go 1.26+.

## Code layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Quick map:

- `pkg/module/`        — public plugin contracts (stable surface)
- `pkg/identity/*`     — built-in identifiers (jwt, apikey, …)
- `pkg/authz/*`        — built-in authorizers (rbac, …)
- `internal/pipeline/` — Identifier→Authorizer→Mutator engine
- `internal/config/`   — YAML config + compiler
- `internal/server/`   — HTTP / gRPC servers
- `cmd/lwauth/`        — main daemon
- `cmd/lwauthctl/`     — CLI helper
- `api/proto/`         — gRPC contracts
- `api/crd/`           — CRD types (M4)
- `deploy/`            — Envoy sample, Helm chart

## Adding a built-in module

1. Implement `module.Identifier`, `module.Authorizer`, or `module.ResponseMutator`.
2. In an `init()`, call `module.RegisterIdentifierFactory("type", factory)`.
3. Blank-import the package from `pkg/builtins/builtins.go`.
4. Add an entry to [examples/config.yaml](examples/config.yaml).

Out-of-process plugins use `api/proto/lightweightauth/plugin/v1/plugin.proto` and live
in the sibling `lightweightauth-plugins` repository.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`). Keep PRs small.

## License

By contributing you agree your contribution is licensed under Apache-2.0.
