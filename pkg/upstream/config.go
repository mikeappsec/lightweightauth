package upstream

import (
	"fmt"
	"time"
)

// Config is the shared YAML/JSON shape every built-in module accepts
// under its `resilience:` key:
//
//	resilience:
//	  breaker:
//	    failureThreshold: 5
//	    coolDown: 30s
//	    halfOpenSuccesses: 1
//	  retries:
//	    max: 2
//	    backoffBase: 50ms
//	    backoffMax: 1s
//	    budgetCapacity: 10
//	    budgetRefillPerSec: 1
//
// All fields are optional; ParseConfig fills in safe defaults so a bare
// `resilience: {}` (or no key at all) still produces a usable Guard.
type Config struct {
	Breaker BreakerYAML `yaml:"breaker" json:"breaker"`
	Retries RetriesYAML `yaml:"retries" json:"retries"`
}

// BreakerYAML mirrors BreakerConfig but with string durations so it can
// be unmarshalled from YAML/JSON without a custom decoder.
type BreakerYAML struct {
	FailureThreshold  int    `yaml:"failureThreshold" json:"failureThreshold"`
	CoolDown          string `yaml:"coolDown" json:"coolDown"`
	HalfOpenSuccesses int    `yaml:"halfOpenSuccesses" json:"halfOpenSuccesses"`
}

// RetriesYAML mirrors the retry-related fields of GuardConfig +
// RetryBudgetConfig with string durations.
type RetriesYAML struct {
	Max                int     `yaml:"max" json:"max"`
	BackoffBase        string  `yaml:"backoffBase" json:"backoffBase"`
	BackoffMax         string  `yaml:"backoffMax" json:"backoffMax"`
	BudgetCapacity     float64 `yaml:"budgetCapacity" json:"budgetCapacity"`
	BudgetRefillPerSec float64 `yaml:"budgetRefillPerSec" json:"budgetRefillPerSec"`
}

// FromMap parses a `resilience` sub-block taken out of a module's raw
// config map. It accepts:
//
//	raw["resilience"]  // map[string]any decoded by sigs.k8s.io/yaml
//
// and returns a usable GuardConfig. A nil or missing block yields a
// zero-retry, default-breaker config — i.e. pure circuit-breaker
// behaviour, which is the safest M11 default for callers that haven't
// opted in.
func FromMap(raw map[string]any) (GuardConfig, error) {
	if raw == nil {
		return GuardConfig{}, nil
	}
	sub, _ := raw["resilience"].(map[string]any)
	if sub == nil {
		return GuardConfig{}, nil
	}
	cfg := GuardConfig{}

	if br, ok := sub["breaker"].(map[string]any); ok && br != nil {
		if v, ok := br["failureThreshold"].(int); ok {
			cfg.Breaker.FailureThreshold = v
		} else if v, ok := br["failureThreshold"].(float64); ok {
			cfg.Breaker.FailureThreshold = int(v)
		}
		if v, ok := br["halfOpenSuccesses"].(int); ok {
			cfg.Breaker.HalfOpenSuccesses = v
		} else if v, ok := br["halfOpenSuccesses"].(float64); ok {
			cfg.Breaker.HalfOpenSuccesses = int(v)
		}
		if v, ok := br["coolDown"].(string); ok && v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return GuardConfig{}, fmt.Errorf("resilience.breaker.coolDown: %w", err)
			}
			cfg.Breaker.CoolDown = d
		}
	}

	if rt, ok := sub["retries"].(map[string]any); ok && rt != nil {
		if v, ok := rt["max"].(int); ok {
			cfg.MaxRetries = v
		} else if v, ok := rt["max"].(float64); ok {
			cfg.MaxRetries = int(v)
		}
		if v, ok := rt["backoffBase"].(string); ok && v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return GuardConfig{}, fmt.Errorf("resilience.retries.backoffBase: %w", err)
			}
			cfg.BackoffBase = d
		}
		if v, ok := rt["backoffMax"].(string); ok && v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return GuardConfig{}, fmt.Errorf("resilience.retries.backoffMax: %w", err)
			}
			cfg.BackoffMax = d
		}
		if v, ok := rt["budgetCapacity"].(float64); ok {
			cfg.Budget.Capacity = v
		} else if v, ok := rt["budgetCapacity"].(int); ok {
			cfg.Budget.Capacity = float64(v)
		}
		if v, ok := rt["budgetRefillPerSec"].(float64); ok {
			cfg.Budget.RefillPerSec = v
		} else if v, ok := rt["budgetRefillPerSec"].(int); ok {
			cfg.Budget.RefillPerSec = float64(v)
		}
	}

	return cfg, nil
}
