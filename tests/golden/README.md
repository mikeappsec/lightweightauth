# Golden — backwards-compatibility lock for v1.0

This directory is the **contract** that turns the v1.0 API freeze
(see DESIGN.md §M12) from a promise into a CI-enforced invariant.

## What it locks

Two surfaces, each in its own subdirectory:

1. `authconfig/` — canonical YAML AuthConfigs. Every file in here MUST
   parse with `internal/config.LoadFile` and successfully `Compile`
   against the built-in module registry, on every commit, forever
   (within v1.x). When we add features, we add **new** files here; we
   never break the existing ones. Removing or renaming a YAML key on
   an existing module is a breaking change and requires a v2 module.

2. `plugin-v1/` — a frozen snapshot of the plugin proto wire shape
   (descriptor set, generated with `protoc --descriptor_set_out`). The
   test asserts the live proto compiled into the binary is wire-
   compatible with this snapshot — fields can be **added** but never
   renumbered or retyped, and required fields cannot be deleted.

A third file, [VERSION](VERSION), names the release these goldens
were captured against. Update it on a deliberate v-bump.

## Why goldens, not just unit tests

Unit tests prove "today's code understands today's config". Goldens
prove "today's code still understands the v1.0-RC config". The
distinction is the entire point of an API freeze: a refactor that
silently drops support for a YAML field would pass unit tests if
both the writer and reader were updated together. Goldens catch
that because the writer (the file on disk) cannot be edited in the
same PR as the reader without an obvious diff.

## How to add a fixture safely

```
# 1. Add a new file, never edit an existing one:
cp examples/dev-local.yaml tests/golden/authconfig/<new-feature>.yaml

# 2. Run the test once to be sure it loads:
go test ./tests/golden/...
```

When you must change the *meaning* of an existing field (i.e. when
v2 lands), copy the old file to `authconfig/legacy/<name>.yaml` and
keep it loading until the deprecation window closes. Never delete.

## How the plugin descriptor lock works

`plugin-v1/plugin.descriptor` is a binary `FileDescriptorSet`
serialized by `protoc`. The Go test reflects over the live
`pluginv1` package and asserts every (message, field number,
field type) tuple present in the descriptor is still present in
the live build. Adding new fields with new numbers passes; renaming
or renumbering fails the test.

To regenerate after a deliberate breaking change (a `plugin/v2`
release), run:

```
make plugin-descriptor
```

…which is wired in `Makefile` and emits a new `plugin.descriptor`
plus updates `VERSION`.
