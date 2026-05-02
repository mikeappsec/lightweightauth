package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func revoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	adminURL := fs.String("admin-url", "", "base URL of the admin endpoint (e.g. https://lwauth:8080)")
	token := fs.String("token", "", "admin JWT bearer token")
	jti := fs.String("jti", "", "revoke by JWT ID (jti claim)")
	tokenHash := fs.String("token-hash", "", "revoke by opaque token hash (sha256)")
	subject := fs.String("subject", "", "revoke all credentials for this subject")
	tenant := fs.String("tenant", "", "tenant scope (required for subject revocation)")
	reason := fs.String("reason", "", "human-readable revocation reason")
	ttl := fs.String("ttl", "", "revocation TTL (e.g. 2h, 24h); default: server default")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	_ = fs.Parse(args)

	if *adminURL == "" {
		fmt.Fprintln(os.Stderr, "error: --admin-url is required")
		os.Exit(1)
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		os.Exit(1)
	}
	if *jti == "" && *tokenHash == "" && *subject == "" {
		fmt.Fprintln(os.Stderr, "error: at least one of --jti, --token-hash, or --subject is required")
		os.Exit(1)
	}

	body := map[string]string{}
	if *jti != "" {
		body["jti"] = *jti
	}
	if *tokenHash != "" {
		body["token_hash"] = *tokenHash
	}
	if *subject != "" {
		body["subject"] = *subject
	}
	if *tenant != "" {
		body["tenant"] = *tenant
	}
	if *reason != "" {
		body["reason"] = *reason
	}
	if *ttl != "" {
		body["ttl"] = *ttl
	}

	data, _ := json.Marshal(body)
	url := *adminURL + "/v1/admin/revoke"

	client := &http.Client{Timeout: 10 * time.Second}
	if *insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // operator-controlled CLI flag
		}
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err == nil {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println(string(respBody))
	}
}
