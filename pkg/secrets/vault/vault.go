// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package vault implements a secrets.Backend for HashiCorp Vault KV v2.
//
// Reference format:
//
//	vault://secret/data/lwauth/jwt-key#current
//	vault://kv/data/myapp/db-password
//
// The path follows Vault's KV v2 API convention (include /data/ segment).
// The fragment (#field) selects a single key from the secret's data map;
// if omitted, the entire JSON-encoded data map is returned.
//
// Authentication methods (tried in order):
//  1. VAULT_TOKEN env var (static token)
//  2. Kubernetes auth (auto-detected in-cluster)
//  3. AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID)
//
// Configuration (passed via BackendConfigs["vault"]):
//
//	addr:      Vault address (default: VAULT_ADDR env)
//	token:     static token (default: VAULT_TOKEN env)
//	role:      Kubernetes auth role (default: "lwauth")
//	mountPath: Kubernetes auth mount (default: "kubernetes")
//	namespace: Vault namespace (for Vault Enterprise)
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/secrets"
)

func init() {
	secrets.RegisterBackend("vault", Factory)
}

// Backend implements secrets.Backend for HashiCorp Vault.
type Backend struct {
	addr      string
	token     string
	namespace string
	client    *http.Client
}

// Factory creates a Vault backend from configuration options.
func Factory(opts map[string]any) (secrets.Backend, error) {
	addr := getOpt(opts, "addr", os.Getenv("VAULT_ADDR"))
	if addr == "" {
		return nil, fmt.Errorf("vault: addr is required (set VAULT_ADDR or config vault.addr)")
	}
	addr = strings.TrimRight(addr, "/")

	// Security: require HTTPS to prevent token exposure over plaintext.
	// Allow HTTP for: localhost (dev/test), .svc.cluster.local (in-cluster),
	// or when explicitly opted in via plainHttp: true.
	plainHTTP := getOptBool(opts, "plainHttp", false)
	if strings.HasPrefix(addr, "http://") && !plainHTTP {
		host := strings.TrimPrefix(addr, "http://")
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" &&
			!strings.HasSuffix(host, ".svc.cluster.local") {
			return nil, fmt.Errorf("vault: addr must use https:// (plaintext http:// only allowed for localhost, *.svc.cluster.local, or with plainHttp: true)")
		}
	}

	token := getOpt(opts, "token", os.Getenv("VAULT_TOKEN"))
	namespace := getOpt(opts, "namespace", os.Getenv("VAULT_NAMESPACE"))

	// If no static token, try Kubernetes auth.
	if token == "" {
		role := getOpt(opts, "role", "lwauth")
		mountPath := getOpt(opts, "mountPath", "kubernetes")
		var err error
		token, err = kubeAuth(addr, namespace, role, mountPath)
		if err != nil {
			// Try AppRole as fallback.
			roleID := os.Getenv("VAULT_ROLE_ID")
			secretID := os.Getenv("VAULT_SECRET_ID")
			if roleID != "" && secretID != "" {
				token, err = appRoleAuth(addr, namespace, roleID, secretID)
				if err != nil {
					return nil, fmt.Errorf("vault: all auth methods failed: %w", err)
				}
			} else {
				return nil, fmt.Errorf("vault: no authentication available (set VAULT_TOKEN, deploy in-cluster, or set VAULT_ROLE_ID+VAULT_SECRET_ID): %w", err)
			}
		}
	}

	return &Backend{
		addr:      addr,
		token:     token,
		namespace: namespace,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Resolve fetches a secret from Vault KV v2.
func (b *Backend) Resolve(ctx context.Context, path, field string) ([]byte, error) {
	// Security: reject path traversal attempts that could escape the /v1/ prefix
	// and access arbitrary Vault endpoints (e.g. /sys/seal-status).
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("vault: path %q contains path traversal", path)
	}

	reqURL := fmt.Sprintf("%s/v1/%s", b.addr, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", b.token)
	if b.namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.namespace)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return nil, fmt.Errorf("vault: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: %s returned %d: %s", path, resp.StatusCode, truncate(body, 256))
	}

	// Parse KV v2 response: {"data": {"data": {...}, "metadata": {...}}}
	var vaultResp struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: decode response for %s: %w", path, err)
	}

	if vaultResp.Data.Data == nil {
		return nil, fmt.Errorf("vault: secret at %s has no data", path)
	}

	// If a field is specified, return just that field.
	if field != "" {
		val, ok := vaultResp.Data.Data[field]
		if !ok {
			return nil, fmt.Errorf("vault: field %q not found in secret %s (available: %v)",
				field, path, mapKeys(vaultResp.Data.Data))
		}
		switch v := val.(type) {
		case string:
			return []byte(v), nil
		default:
			encoded, _ := json.Marshal(v)
			return encoded, nil
		}
	}

	// No field specified — return the entire data map as JSON.
	encoded, err := json.Marshal(vaultResp.Data.Data)
	if err != nil {
		return nil, fmt.Errorf("vault: encode data for %s: %w", path, err)
	}
	return encoded, nil
}

// Close releases the HTTP client resources.
func (b *Backend) Close() error {
	b.client.CloseIdleConnections()
	return nil
}

// --- Authentication helpers ---

// kubeAuth authenticates via Vault's Kubernetes auth method using the
// in-cluster service account token.
func kubeAuth(addr, namespace, role, mountPath string) (string, error) {
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("kubernetes auth: read SA token: %w", err)
	}

	payload := fmt.Sprintf(`{"role":%q,"jwt":%q}`, role, string(saToken))
	loginURL := fmt.Sprintf("%s/v1/auth/%s/login", addr, mountPath)

	return doLogin(loginURL, namespace, payload)
}

// appRoleAuth authenticates via Vault's AppRole method.
func appRoleAuth(addr, namespace, roleID, secretID string) (string, error) {
	payload := fmt.Sprintf(`{"role_id":%q,"secret_id":%q}`, roleID, secretID)
	loginURL := fmt.Sprintf("%s/v1/auth/approle/login", addr)

	return doLogin(loginURL, namespace, payload)
}

func doLogin(loginURL, namespace, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("vault login request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault login returned %d: %s", resp.StatusCode, truncate(body, 256))
	}

	var loginResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("vault login decode: %w", err)
	}
	if loginResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login: empty client_token in response")
	}
	return loginResp.Auth.ClientToken, nil
}

// --- Utilities ---

func getOpt(opts map[string]any, key, fallback string) string {
	if opts == nil {
		return fallback
	}
	if v, ok := opts[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func getOptBool(opts map[string]any, key string, fallback bool) bool {
	if opts == nil {
		return fallback
	}
	if v, ok := opts[key].(bool); ok {
		return v
	}
	return fallback
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
