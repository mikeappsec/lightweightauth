// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package bundle implements packaging, publishing, and pulling of
// LightweightAuth policy bundles as OCI artifacts.
//
// A bundle is a directory containing:
//
//	bundle.yaml        — metadata (name, version, description, policies list)
//	policies/          — one or more AuthConfig YAML files
//
// Bundles are pushed to OCI registries as single-layer artifacts with
// media type application/vnd.lwauth.bundle.v1.tar+gzip. Consumers pull
// bundles via lwauthctl and apply the contained AuthConfig files.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// MediaType is the OCI artifact media type for lwauth policy bundles.
const MediaType = "application/vnd.lwauth.bundle.v1.tar+gzip"

// ArtifactType is the OCI artifact type annotation.
const ArtifactType = "application/vnd.lwauth.bundle.v1"

// MaxBundleSize is the maximum uncompressed bundle size (10 MiB).
const MaxBundleSize = 10 << 20

// Metadata describes a policy bundle.
type Metadata struct {
	Name        string   `yaml:"name" json:"name"`
	Version     string   `yaml:"version" json:"version"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	Author      string   `yaml:"author,omitempty" json:"author,omitempty"`
	License     string   `yaml:"license,omitempty" json:"license,omitempty"`
	Policies    []string `yaml:"policies" json:"policies"`
}

// LoadMetadata reads and validates a bundle.yaml from the given directory.
func LoadMetadata(dir string) (*Metadata, error) {
	data, err := os.ReadFile(filepath.Join(dir, "bundle.yaml"))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	var m Metadata
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("bundle: parse bundle.yaml: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks required fields and policy file references.
func (m *Metadata) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("bundle: name is required")
	}
	if m.Version == "" {
		return fmt.Errorf("bundle: version is required")
	}
	if len(m.Policies) == 0 {
		return fmt.Errorf("bundle: at least one policy file is required")
	}
	for _, p := range m.Policies {
		if strings.Contains(p, "..") || filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
			return fmt.Errorf("bundle: policy path %q must be relative and not traverse parent", p)
		}
	}
	return nil
}

// Pack creates a gzipped tar archive from a bundle directory.
// It includes bundle.yaml and all referenced policy files.
func Pack(dir string) ([]byte, *Metadata, error) {
	meta, err := LoadMetadata(dir)
	if err != nil {
		return nil, nil, err
	}

	// Pre-check total uncompressed size.
	var totalSize int64
	files := append([]string{"bundle.yaml"}, meta.Policies...)
	for _, p := range files {
		info, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: %w", err)
		}
		totalSize += info.Size()
		if totalSize > int64(MaxBundleSize) {
			return nil, nil, fmt.Errorf("bundle: total uncompressed size exceeds limit %d", MaxBundleSize)
		}
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Add bundle.yaml
	if err := addFile(tw, dir, "bundle.yaml"); err != nil {
		return nil, nil, err
	}

	// Add each policy file
	for _, p := range meta.Policies {
		if err := addFile(tw, dir, p); err != nil {
			return nil, nil, fmt.Errorf("bundle: policy %q: %w", p, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, nil, fmt.Errorf("bundle: tar close: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, nil, fmt.Errorf("bundle: gzip close: %w", err)
	}

	return buf.Bytes(), meta, nil
}

// maxEntries is the maximum number of tar entries allowed in a bundle.
const maxEntries = 1000

// Unpack extracts a bundle tar.gz into the destination directory.
func Unpack(data []byte, destDir string) (*Metadata, error) {
	if len(data) > MaxBundleSize {
		return nil, fmt.Errorf("bundle: data size %d exceeds limit %d", len(data), MaxBundleSize)
	}

	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("bundle: gzip: %w", err)
	}
	defer gr.Close()

	// BN5: Wrap gzip reader with a limit to prevent decompression bombs.
	lr := io.LimitReader(gr, MaxBundleSize+1)
	tr := tar.NewReader(lr)

	var totalBytes int64
	var entryCount int
	absDir, err := filepath.Abs(destDir)
	if err != nil {
		return nil, fmt.Errorf("bundle: abs destDir: %w", err)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: tar: %w", err)
		}

		// BN6: Limit number of entries to prevent inode exhaustion.
		entryCount++
		if entryCount > maxEntries {
			return nil, fmt.Errorf("bundle: too many entries (%d > %d)", entryCount, maxEntries)
		}

		// BN1: Reject symlinks, hardlinks, and other non-regular entries.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("bundle: unsupported entry type %d for %q", hdr.Typeflag, hdr.Name)
		}

		// Security: reject absolute paths and traversal.
		clean := filepath.Clean(hdr.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return nil, fmt.Errorf("bundle: unsafe path in archive: %q", hdr.Name)
		}

		totalBytes += hdr.Size
		if totalBytes > MaxBundleSize {
			return nil, fmt.Errorf("bundle: uncompressed content exceeds %d bytes", MaxBundleSize)
		}

		dest := filepath.Join(destDir, clean)

		// BN2: Validate containment — resolved path must be within destDir.
		absDest, err := filepath.Abs(dest)
		if err != nil {
			return nil, fmt.Errorf("bundle: abs path: %w", err)
		}
		if !strings.HasPrefix(absDest, absDir+string(os.PathSeparator)) && absDest != absDir {
			return nil, fmt.Errorf("bundle: path escapes destination: %q", hdr.Name)
		}

		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return nil, fmt.Errorf("bundle: mkdir %q: %w", dest, err)
			}
			continue
		}

		dir := filepath.Dir(dest)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("bundle: mkdir %q: %w", dir, err)
		}

		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, fmt.Errorf("bundle: create %q: %w", dest, err)
		}
		if _, err := io.Copy(f, io.LimitReader(tr, hdr.Size)); err != nil {
			f.Close()
			return nil, fmt.Errorf("bundle: write %q: %w", dest, err)
		}
		f.Close()
	}

	return LoadMetadata(destDir)
}

// PushOptions configures a bundle push to an OCI registry.
type PushOptions struct {
	Registry string // e.g. "ghcr.io/org/policies"
	Username string
	Password string
}

// Push packages a bundle directory and pushes it to an OCI registry.
// The tag is derived from the bundle version.
func Push(ctx context.Context, dir string, opts PushOptions) (string, error) {
	data, meta, err := Pack(dir)
	if err != nil {
		return "", err
	}

	store := memory.New()

	// Push the bundle layer.
	layerDesc, err := pushBlob(ctx, store, MediaType, data)
	if err != nil {
		return "", fmt.Errorf("bundle: push layer: %w", err)
	}

	// Build manifest with annotations.
	annotations := map[string]string{
		"org.opencontainers.image.title":   meta.Name,
		"org.opencontainers.image.version": meta.Version,
	}
	if meta.Description != "" {
		annotations["org.opencontainers.image.description"] = meta.Description
	}
	if meta.Author != "" {
		annotations["org.opencontainers.image.authors"] = meta.Author
	}
	if meta.License != "" {
		annotations["org.opencontainers.image.licenses"] = meta.License
	}

	// Push empty config blob.
	emptyConfig := []byte("{}")
	configDesc, err := pushBlob(ctx, store, ArtifactType, emptyConfig)
	if err != nil {
		return "", fmt.Errorf("bundle: push config: %w", err)
	}

	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactType,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{layerDesc},
		Annotations:  annotations,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("bundle: marshal manifest: %w", err)
	}

	manifestDesc, err := pushBlob(ctx, store, ocispec.MediaTypeImageManifest, manifestJSON)
	if err != nil {
		return "", fmt.Errorf("bundle: push manifest: %w", err)
	}

	// Tag the manifest.
	if err := store.Tag(ctx, manifestDesc, meta.Version); err != nil {
		return "", fmt.Errorf("bundle: tag: %w", err)
	}

	// Copy to remote.
	repo, err := newRepository(opts)
	if err != nil {
		return "", err
	}
	desc, err := oras.Copy(ctx, store, meta.Version, repo, meta.Version, oras.DefaultCopyOptions)
	if err != nil {
		return "", fmt.Errorf("bundle: push to registry: %w", err)
	}

	return desc.Digest.String(), nil
}

// PullOptions configures a bundle pull from an OCI registry.
type PullOptions struct {
	Registry string // e.g. "ghcr.io/org/policies"
	Tag      string // version tag or digest
	Username string
	Password string
}

// Pull downloads a bundle from an OCI registry and unpacks it into destDir.
func Pull(ctx context.Context, destDir string, opts PullOptions) (*Metadata, error) {
	repo, err := newRepository(PushOptions{
		Registry: opts.Registry,
		Username: opts.Username,
		Password: opts.Password,
	})
	if err != nil {
		return nil, err
	}

	store := memory.New()
	desc, err := oras.Copy(ctx, repo, opts.Tag, store, opts.Tag, oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("bundle: pull from registry: %w", err)
	}

	// Fetch manifest to find the layer.
	manifestData, err := fetchBlob(ctx, store, desc)
	if err != nil {
		return nil, fmt.Errorf("bundle: fetch manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("bundle: manifest has no layers")
	}

	// Find the bundle layer.
	var bundleLayer ocispec.Descriptor
	for _, l := range manifest.Layers {
		if l.MediaType == MediaType {
			bundleLayer = l
			break
		}
	}
	if bundleLayer.Size == 0 {
		return nil, fmt.Errorf("bundle: no layer with media type %s", MediaType)
	}

	data, err := fetchBlob(ctx, store, bundleLayer)
	if err != nil {
		return nil, fmt.Errorf("bundle: fetch layer: %w", err)
	}

	return Unpack(data, destDir)
}

func newRepository(opts PushOptions) (*remote.Repository, error) {
	repo, err := remote.NewRepository(opts.Registry)
	if err != nil {
		return nil, fmt.Errorf("bundle: invalid registry %q: %w", opts.Registry, err)
	}
	if opts.Username != "" {
		repo.Client = &auth.Client{
			Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
				Username: opts.Username,
				Password: opts.Password,
			}),
		}
	}
	return repo, nil
}

func pushBlob(ctx context.Context, store *memory.Store, mediaType string, data []byte) (ocispec.Descriptor, error) {
	h := sha256.Sum256(data)
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.NewDigestFromBytes(digest.SHA256, h[:]),
		Size:      int64(len(data)),
	}
	return desc, store.Push(ctx, desc, bytes.NewReader(data))
}

func fetchBlob(ctx context.Context, store *memory.Store, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := store.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, MaxBundleSize))
}

func addFile(tw *tar.Writer, baseDir, relPath string) error {
	full := filepath.Join(baseDir, relPath)
	info, err := os.Stat(full)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = filepath.ToSlash(relPath)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}
