// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net"
	"net/url"
	"strings"
)

// validateAdminURL checks that a user-supplied AdminURL is safe to
// register as a scrape/proxy target. It blocks:
//   - non-http(s) schemes
//   - loopback addresses (127.0.0.0/8, ::1)
//   - link-local addresses (169.254.0.0/16, fe80::/10) — covers AWS/GCP/Azure IMDS
//   - RFC1918 private ranges (10/8, 172.16/12, 192.168/16) — optional; see allowPrivate
//   - cloud metadata hostnames (169.254.169.254, metadata.google.internal, etc.)
//   - URLs without a host
//
// allowPrivate should be false for user-facing endpoints (probe, register)
// where the caller is untrusted. In-cluster auto-discovery bypasses this
// check entirely because the discovery watcher resolves Kubernetes Service
// IPs directly — those are inherently private and trusted.
//
// Returns nil if safe, or an error with a human-readable reason.
func validateAdminURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errBlockedHost("non-http(s) scheme")
	}
	host := u.Hostname()
	if host == "" {
		return errBlockedHost("empty host")
	}
	return validateHost(host, allowPrivate)
}

// validateHost resolves the hostname and checks every resolved IP
// against loopback, link-local, private, and metadata ranges.
func validateHost(host string, allowPrivate bool) error {
	// Fast path: check known metadata hostnames first (no DNS needed).
	if isMetadataHost(host) {
		return errBlockedHost("cloud metadata endpoint")
	}
	// If it's an IP literal, validate directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		return validateIP(ip, allowPrivate)
	}
	// Resolve and check every IP — guards against DNS rebinding where
	// the hostname resolves to a public IP at validation time but a
	// private IP at request time. We resolve once here; the actual
	// HTTP client may re-resolve, but this catches the common case.
	ips, err := net.LookupIP(host)
	if err != nil {
		// Fail closed: an attacker controlling the queried domain's DNS
		// can make this lookup fail on demand (e.g. SERVFAIL) while a
		// later lookup from the actual outbound client succeeds with an
		// internal/metadata IP, bypassing validation entirely. A
		// resolution failure must be rejected, not treated as "unknown,
		// so allow" — the outbound request would fail on the same
		// unresolvable host anyway in the benign case.
		return errBlockedHost("host resolution failed")
	}
	for _, ip := range ips {
		if err := validateIP(ip, allowPrivate); err != nil {
			return err
		}
	}
	return nil
}

func validateIP(ip net.IP, allowPrivate bool) error {
	if ip.IsLoopback() {
		return errBlockedHost("loopback address")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return errBlockedHost("link-local address (cloud metadata range)")
	}
	if !allowPrivate && ip.IsPrivate() {
		return errBlockedHost("private RFC1918 address")
	}
	if ip.IsUnspecified() {
		return errBlockedHost("unspecified address (0.0.0.0/::)")
	}
	return nil
}

// isMetadataHost checks against known cloud metadata hostnames.
func isMetadataHost(host string) bool {
	metadataHosts := []string{
		"169.254.169.254",          // AWS / GCP / OCI / Azure IMDS
		"metadata.google.internal", // GCP IMDS
		"instance-data",            // Oracle Cloud
		"metadata.azure.com",       // Azure IMDS
		"100.100.100.200",          // Alibaba Cloud
		"169.254.170.2",            // ECS task metadata
		"fd00:ec2::254",            // AWS IMDS IPv6
	}
	for _, h := range metadataHosts {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

type errBlockedHost string

func (e errBlockedHost) Error() string { return "blocked host: " + string(e) }