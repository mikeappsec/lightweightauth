package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func sign(secret, msg []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func newID(t *testing.T) module.Identifier {
	t.Helper()
	id, err := factory("hmac", map[string]any{
		"keys": map[string]any{
			"abc": map[string]any{
				"secret":  base64.StdEncoding.EncodeToString([]byte("supersecret")),
				"subject": "service-a",
				"roles":   []any{"machine"},
			},
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return id
}

func TestHMAC_Roundtrip(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	body := []byte(`{"x":1}`)
	bodyHash := sha256.Sum256(body)
	canon := strings.Join([]string{
		"POST", "/things", now,
		base64.StdEncoding.EncodeToString(bodyHash[:]),
	}, "\n")
	sig := sign([]byte("supersecret"), []byte(canon))
	auth := `HMAC-SHA256 keyId="abc", signature="` + sig + `"`

	got, err := id.Identify(context.Background(), &module.Request{
		Method: "POST",
		Path:   "/things",
		Body:   body,
		Headers: map[string][]string{
			"Authorization": {auth},
			"Date":          {now},
		},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "service-a" {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.Claims["keyId"] != "abc" {
		t.Errorf("keyId claim = %v", got.Claims["keyId"])
	}
}

func TestHMAC_Tampered(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	auth := `HMAC-SHA256 keyId="abc", signature="` + base64.StdEncoding.EncodeToString([]byte("nope")) + `"`
	_, err := id.Identify(context.Background(), &module.Request{
		Method:  "GET",
		Path:    "/things",
		Headers: map[string][]string{"Authorization": {auth}, "Date": {now}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestHMAC_ClockSkew(t *testing.T) {
	t.Parallel()
	id := newID(t)
	stale := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	bodyHash := sha256.Sum256(nil)
	canon := strings.Join([]string{"GET", "/x", stale, base64.StdEncoding.EncodeToString(bodyHash[:])}, "\n")
	sig := sign([]byte("supersecret"), []byte(canon))
	auth := `HMAC-SHA256 keyId="abc", signature="` + sig + `"`
	_, err := id.Identify(context.Background(), &module.Request{
		Method:  "GET",
		Path:    "/x",
		Headers: map[string][]string{"Authorization": {auth}, "Date": {stale}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (skew)", err)
	}
}

func TestHMAC_UnknownKeyID(t *testing.T) {
	t.Parallel()
	id := newID(t)
	now := time.Now().UTC().Format(time.RFC3339)
	auth := `HMAC-SHA256 keyId="ghost", signature="` + base64.StdEncoding.EncodeToString([]byte("x")) + `"`
	_, err := id.Identify(context.Background(), &module.Request{
		Method:  "GET",
		Path:    "/x",
		Headers: map[string][]string{"Authorization": {auth}, "Date": {now}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestHMAC_NoHeaderNoMatch(t *testing.T) {
	t.Parallel()
	id := newID(t)
	_, err := id.Identify(context.Background(), &module.Request{Method: "GET", Path: "/x"})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}
