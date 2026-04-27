package apikey

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Store is the abstraction the apikey identifier uses to look up keys.
// Implementations MUST be safe for concurrent reads.
//
// Two flavours ship in core:
//
//   - StaticStore: legacy plaintext map (M1, retained for tests/dev only).
//   - HashedStore: argon2id-hashed entries; the wire key is the only
//     plaintext, never the disk representation.
//
// Redis and Vault backends live in lightweightauth-plugins (M10).
type Store interface {
	Lookup(presented string) (entry, bool)
}

// HashedStore holds argon2id digests. Entries are keyed by an "id"
// chosen by the operator (e.g. the first 8 chars of the original key, or
// "team-foo-2025"). The id is published on Identity.Claims["keyId"] so
// audit logs can attribute requests without storing plaintext keys.
type HashedStore struct {
	mu      sync.RWMutex
	entries []hashedEntry
}

type hashedEntry struct {
	id    string
	salt  []byte
	digest []byte
	subject string
	roles []string
}

// argon2id parameters (interactive profile from RFC 9106 §4):
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// HashKey returns a serialisable encoded hash:
//
//	$argon2id$v=19$m=65536,t=2,p=1$<saltb64>$<digestb64>
func HashKey(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("apikey: salt: %w", err)
	}
	d := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(d),
	), nil
}

// AddHashed installs an entry whose digest is provided in encoded form
// (HashKey output). Returns an error on malformed input.
func (h *HashedStore) AddHashed(id, encoded, subject string, roles []string) error {
	salt, digest, err := parseEncoded(encoded)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, hashedEntry{
		id: id, salt: salt, digest: digest, subject: subject, roles: roles,
	})
	return nil
}

// AddPlaintext is a convenience for tests / first-time provisioning.
// In production, hashes should be precomputed via HashKey and stored
// out-of-band (the file backend reads them as-is).
func (h *HashedStore) AddPlaintext(id, plain, subject string, roles []string) error {
	enc, err := HashKey(plain)
	if err != nil {
		return err
	}
	return h.AddHashed(id, enc, subject, roles)
}

func (h *HashedStore) Lookup(presented string) (entry, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, e := range h.entries {
		d := argon2.IDKey([]byte(presented), e.salt, argonTime, argonMemory, argonThreads, argonKeyLen)
		if subtle.ConstantTimeCompare(d, e.digest) == 1 {
			return entry{subject: e.subject, roles: append([]string(nil), e.roles...), keyID: e.id}, true
		}
	}
	return entry{}, false
}

// LoadHashedStoreFromFile reads a flat file:
//
//	# id  encoded-hash                                                                  subject  role1,role2
//	abc   $argon2id$v=19$m=65536,t=2,p=1$<salt>$<digest>                                 alice    admin,editor
//
// Whitespace-separated, '#' starts a comment, blank lines OK. Used by
// ConfigMap / Secret-mounted backends.
func LoadHashedStoreFromFile(path string) (*HashedStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("apikey: open %s: %w", path, err)
	}
	defer f.Close()

	store := &HashedStore{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) < 3 {
			return nil, fmt.Errorf("apikey: %s:%d: expected `id hash subject [roles]`", path, line)
		}
		id, encoded, subject := fields[0], fields[1], fields[2]
		var roles []string
		if len(fields) > 3 {
			roles = strings.Split(fields[3], ",")
		}
		if err := store.AddHashed(id, encoded, subject, roles); err != nil {
			return nil, fmt.Errorf("apikey: %s:%d: %w", path, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("apikey: scan %s: %w", path, err)
	}
	return store, nil
}

// LoadHashedStoreFromDir is the K8s-friendly backend: each file in dir
// is a single hash (Secret volume layout, where each key is mounted as a
// file). The filename becomes the id; the file contents are
//
//	<encoded-hash>\n<subject>\n[<role1,role2>\n]
func LoadHashedStoreFromDir(dir string) (*HashedStore, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("apikey: read dir %s: %w", dir, err)
	}
	store := &HashedStore{}
	for _, ent := range ents {
		if ent.IsDir() || strings.HasPrefix(ent.Name(), "..") {
			// Skip K8s' atomic-rename ..data symlinks.
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, fmt.Errorf("apikey: read %s: %w", ent.Name(), err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) < 2 {
			return nil, fmt.Errorf("apikey: %s: expected `<hash>\\n<subject>` minimum", ent.Name())
		}
		var roles []string
		if len(lines) > 2 {
			roles = strings.Split(lines[2], ",")
		}
		if err := store.AddHashed(ent.Name(), lines[0], lines[1], roles); err != nil {
			return nil, fmt.Errorf("apikey: %s: %w", ent.Name(), err)
		}
	}
	return store, nil
}

// parseEncoded decodes the standard argon2id encoded hash format.
func parseEncoded(s string) (salt, digest []byte, err error) {
	if !strings.HasPrefix(s, "$argon2id$") {
		return nil, nil, errors.New("apikey: not an argon2id hash")
	}
	parts := strings.Split(s, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<digest>"]
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("apikey: malformed hash: %d parts", len(parts))
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("apikey: salt b64: %w", err)
	}
	digest, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("apikey: digest b64: %w", err)
	}
	return salt, digest, nil
}

// staticStore is the plaintext-map backend kept for tests and dev. It
// hashes nothing and is NOT for production.
type staticStore struct {
	keys map[string]entry
}

func (s *staticStore) Lookup(presented string) (entry, bool) {
	e, ok := s.keys[presented]
	return e, ok
}

// shortID is a deterministic 8-char id for plaintext keys, used purely
// for audit-log breadcrumbs (Claims["keyId"]). Never reverse-able.
func shortID(s string) string {
	h := argon2.IDKey([]byte(s), []byte("apikey-id"), 1, 8*1024, 1, 8)
	return hex.EncodeToString(h)[:8]
}
