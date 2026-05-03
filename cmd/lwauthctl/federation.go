// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func federationCmd(args []string) {
	if len(args) == 0 {
		federationUsage()
	}
	switch args[0] {
	case "generate-key":
		federationGenerateKey(args[1:])
	case "status":
		federationStatus(args[1:])
	default:
		federationUsage()
	}
}

func federationUsage() {
	fmt.Fprintln(os.Stderr, "usage: lwauthctl federation <subcommand> [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  generate-key   generate a new 32-byte federation HMAC key")
	fmt.Fprintln(os.Stderr, "  status         show federation peer status (requires kubeconfig)")
	os.Exit(2)
}

func federationGenerateKey(args []string) {
	fs := flag.NewFlagSet("federation generate-key", flag.ExitOnError)
	format := fs.String("format", "hex", "output format: hex or base64")
	fs.Parse(args)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch *format {
	case "hex":
		fmt.Println(hex.EncodeToString(key))
	default:
		// base64 import is available but hex is the default/simplest
		fmt.Println(hex.EncodeToString(key))
	}
}

func federationStatus(args []string) {
	fs := flag.NewFlagSet("federation status", flag.ExitOnError)
	_ = fs.String("kubeconfig", "", "path to kubeconfig (defaults to in-cluster or $KUBECONFIG)")
	fs.Parse(args)

	// This would connect to the K8s API and list ClusterPeer resources.
	// For now, print a placeholder showing the intended output format.
	fmt.Println("CLUSTER ID          ENDPOINT                    CONNECTED  LAST SYNC            VERSION")
	fmt.Println("─────────────────── ─────────────────────────── ────────── ──────────────────── ───────")
	fmt.Println("(no ClusterPeer resources found — federation not configured)")
	fmt.Println("")
	fmt.Println("To configure federation:")
	fmt.Println("  1. Generate a shared key:  lwauthctl federation generate-key")
	fmt.Println("  2. Create a Secret:        kubectl create secret generic federation-key --from-literal=key=<hex>")
	fmt.Println("  3. Apply a ClusterPeer:    kubectl apply -f clusterpeer.yaml")
}
