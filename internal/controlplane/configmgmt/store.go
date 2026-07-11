// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package configmgmt handles AuthConfig push, version history, and rollback.
package configmgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ConfigVersion represents a point-in-time snapshot of an instance's config.
type ConfigVersion struct {
	Version   int       `json:"version"`
	Content   string    `json:"content"`
	Author    string    `json:"author,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Comment   string    `json:"comment,omitempty"`
	// Rollback indicates this version was created by a rollback to TargetVersion.
	Rollback      bool `json:"rollback,omitempty"`
	TargetVersion int  `json:"targetVersion,omitempty"`
}

// instanceKey is cluster/name.
func instanceKey(cluster, name string) string {
	return cluster + "/" + name
}

// Store tracks config version history per instance.
type Store struct {
	mu       sync.RWMutex
	versions map[string][]ConfigVersion // key: cluster/name
}

// NewStore creates an empty config store.
func NewStore() *Store {
	return &Store{
		versions: make(map[string][]ConfigVersion),
	}
}

// Push stores a new config version for an instance. Returns the new version number.
func (s *Store) Push(cluster, name, content, author, comment string) (ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := instanceKey(cluster, name)
	history := s.versions[key]

	nextVersion := 1
	if len(history) > 0 {
		nextVersion = history[len(history)-1].Version + 1
	}

	v := ConfigVersion{
		Version:   nextVersion,
		Content:   content,
		Author:    author,
		Timestamp: time.Now(),
		Comment:   comment,
	}
	s.versions[key] = append(history, v)
	return v, nil
}

// History returns all config versions for an instance, ordered oldest-first.
func (s *Store) History(cluster, name string) []ConfigVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[instanceKey(cluster, name)]
}

// GetVersion returns a specific version.
func (s *Store) GetVersion(cluster, name string, version int) (ConfigVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range s.versions[instanceKey(cluster, name)] {
		if v.Version == version {
			return v, true
		}
	}
	return ConfigVersion{}, false
}

// Current returns the latest config version.
func (s *Store) Current(cluster, name string) (ConfigVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := s.versions[instanceKey(cluster, name)]
	if len(history) == 0 {
		return ConfigVersion{}, false
	}
	return history[len(history)-1], true
}

// Rollback creates a new version that copies the content from a prior version.
func (s *Store) Rollback(cluster, name string, targetVersion int, author string) (ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := instanceKey(cluster, name)
	history := s.versions[key]

	// Find the target version.
	var target *ConfigVersion
	for i := range history {
		if history[i].Version == targetVersion {
			target = &history[i]
			break
		}
	}
	if target == nil {
		return ConfigVersion{}, fmt.Errorf("version %d not found", targetVersion)
	}

	nextVersion := 1
	if len(history) > 0 {
		nextVersion = history[len(history)-1].Version + 1
	}

	v := ConfigVersion{
		Version:       nextVersion,
		Content:       target.Content,
		Author:        author,
		Timestamp:     time.Now(),
		Comment:       fmt.Sprintf("Rollback to version %d", targetVersion),
		Rollback:      true,
		TargetVersion: targetVersion,
	}
	s.versions[key] = append(history, v)
	return v, nil
}

// Diff returns the content of two versions for comparison.
func (s *Store) Diff(cluster, name string, fromVersion, toVersion int) (from, to string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := s.versions[instanceKey(cluster, name)]
	var fromCV, toCV *ConfigVersion
	for i := range history {
		if history[i].Version == fromVersion {
			fromCV = &history[i]
		}
		if history[i].Version == toVersion {
			toCV = &history[i]
		}
	}
	if fromCV == nil {
		return "", "", fmt.Errorf("version %d not found", fromVersion)
	}
	if toCV == nil {
		return "", "", fmt.Errorf("version %d not found", toVersion)
	}
	return fromCV.Content, toCV.Content, nil
}

// ValidateConfig performs basic YAML/JSON validation.
func ValidateConfig(content string) error {
	// Attempt JSON parse. Config can be JSON or YAML; for now validate
	// it's at least valid JSON (AuthConfig spec is JSON-serializable).
	var raw map[string]any
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

// PushConfig validates and stores a new config, returning the version.
func (s *Store) PushConfig(ctx context.Context, cluster, name, content, author, comment string) (ConfigVersion, error) {
	if err := ValidateConfig(content); err != nil {
		return ConfigVersion{}, err
	}
	return s.Push(cluster, name, content, author, comment)
}
