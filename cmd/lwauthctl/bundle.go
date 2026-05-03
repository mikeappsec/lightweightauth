// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/mikeappsec/lightweightauth/pkg/bundle"
)

func bundleCmd(args []string) {
	if len(args) == 0 {
		bundleUsage()
	}
	switch args[0] {
	case "push":
		bundlePush(args[1:])
	case "pull":
		bundlePull(args[1:])
	case "pack":
		bundlePack(args[1:])
	case "inspect":
		bundleInspect(args[1:])
	default:
		bundleUsage()
	}
}

func bundleUsage() {
	fmt.Fprintln(os.Stderr, "usage: lwauthctl bundle <subcommand> [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  push --dir DIR --registry REG [--username U --password P]")
	fmt.Fprintln(os.Stderr, "       package and push a policy bundle to an OCI registry")
	fmt.Fprintln(os.Stderr, "  pull --registry REG --tag TAG --out DIR [--username U --password P]")
	fmt.Fprintln(os.Stderr, "       pull a policy bundle from an OCI registry")
	fmt.Fprintln(os.Stderr, "  pack --dir DIR --out FILE")
	fmt.Fprintln(os.Stderr, "       package a bundle directory into a local .tar.gz file")
	fmt.Fprintln(os.Stderr, "  inspect --dir DIR")
	fmt.Fprintln(os.Stderr, "       validate and display bundle metadata")
	os.Exit(2)
}

func bundlePush(args []string) {
	fs := flag.NewFlagSet("bundle push", flag.ExitOnError)
	dir := fs.String("dir", ".", "bundle directory")
	registry := fs.String("registry", "", "OCI registry reference (e.g. ghcr.io/org/policies/my-bundle)")
	username := fs.String("username", "", "registry username (or use $LWAUTH_REGISTRY_USERNAME)")
	password := fs.String("password", "", "registry password (or use $LWAUTH_REGISTRY_PASSWORD)")
	fs.Parse(args)

	if *registry == "" {
		fmt.Fprintln(os.Stderr, "error: --registry is required")
		os.Exit(1)
	}

	user := envOr(*username, "LWAUTH_REGISTRY_USERNAME")
	pass := envOr(*password, "LWAUTH_REGISTRY_PASSWORD")

	ctx := context.Background()
	digest, err := bundle.Push(ctx, *dir, bundle.PushOptions{
		Registry: *registry,
		Username: user,
		Password: pass,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pushed: %s@%s\n", *registry, digest)
}

func bundlePull(args []string) {
	fs := flag.NewFlagSet("bundle pull", flag.ExitOnError)
	registry := fs.String("registry", "", "OCI registry reference")
	tag := fs.String("tag", "", "version tag or digest to pull")
	out := fs.String("out", ".", "destination directory")
	username := fs.String("username", "", "registry username (or use $LWAUTH_REGISTRY_USERNAME)")
	password := fs.String("password", "", "registry password (or use $LWAUTH_REGISTRY_PASSWORD)")
	fs.Parse(args)

	if *registry == "" || *tag == "" {
		fmt.Fprintln(os.Stderr, "error: --registry and --tag are required")
		os.Exit(1)
	}

	user := envOr(*username, "LWAUTH_REGISTRY_USERNAME")
	pass := envOr(*password, "LWAUTH_REGISTRY_PASSWORD")

	ctx := context.Background()
	meta, err := bundle.Pull(ctx, *out, bundle.PullOptions{
		Registry: *registry,
		Tag:      *tag,
		Username: user,
		Password: pass,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pulled: %s v%s (%d policies)\n", meta.Name, meta.Version, len(meta.Policies))
}

func bundlePack(args []string) {
	fs := flag.NewFlagSet("bundle pack", flag.ExitOnError)
	dir := fs.String("dir", ".", "bundle directory")
	out := fs.String("out", "", "output .tar.gz file path")
	fs.Parse(args)

	if *out == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		os.Exit(1)
	}

	data, meta, err := bundle.Pack(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("packed: %s v%s → %s (%d bytes, %d policies)\n",
		meta.Name, meta.Version, *out, len(data), len(meta.Policies))
}

func bundleInspect(args []string) {
	fs := flag.NewFlagSet("bundle inspect", flag.ExitOnError)
	dir := fs.String("dir", ".", "bundle directory")
	fs.Parse(args)

	meta, err := bundle.LoadMetadata(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Name:        %s\n", meta.Name)
	fmt.Printf("Version:     %s\n", meta.Version)
	if meta.Description != "" {
		fmt.Printf("Description: %s\n", meta.Description)
	}
	if meta.Author != "" {
		fmt.Printf("Author:      %s\n", meta.Author)
	}
	if meta.License != "" {
		fmt.Printf("License:     %s\n", meta.License)
	}
	if len(meta.Keywords) > 0 {
		fmt.Printf("Keywords:    %v\n", meta.Keywords)
	}
	fmt.Printf("Policies:\n")
	for _, p := range meta.Policies {
		fmt.Printf("  - %s\n", p)
	}
}

func envOr(explicit, envKey string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv(envKey)
}
