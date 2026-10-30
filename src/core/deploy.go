package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Deployment describes how the project actually runs - what an advisory's preconditions
// are checked against. Kept to facts an operator can state with confidence; anything
// left out is treated as unknown, never as safe.
type Deployment struct {
	// Platform is the OS the production install runs on: linux, windows or macos.
	Platform string `yaml:"platform" json:"platform,omitempty"`
	// Container: runs in a container (its own filesystem and process namespace).
	Container bool `yaml:"container" json:"container"`
	// SharedHost: other, untrusted local users or processes share the machine/container.
	SharedHost bool `yaml:"shared_host" json:"shared_host"`
	// OutboundTLS: makes HTTPS/TLS connections to other services.
	OutboundTLS bool `yaml:"outbound_tls" json:"outbound_tls"`
	// Exposed lists what's reachable from outside, e.g. "HTTP API on the tailnet".
	Exposed []string `yaml:"exposed" json:"exposed,omitempty"`
	// UntrustedInput lists input an attacker could control, e.g. "uploaded media files".
	UntrustedInput []string `yaml:"untrusted_input" json:"untrusted_input,omitempty"`
	// Notes is anything else worth knowing, in prose.
	Notes string `yaml:"notes" json:"notes,omitempty"`
}

// ReadDeployment reads a picard.yaml.
func ReadDeployment(path string) (*Deployment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var d Deployment
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return &d, nil
}

// Describe renders the deployment for an assessment prompt.
func (d *Deployment) Describe() string {
	if d == nil {
		return "Unknown - no deployment description given. Treat every precondition as possibly met."
	}

	data, _ := yaml.Marshal(d)

	return string(data)
}

// Hash identifies this deployment description, so cached assessments made against a
// different one aren't reused.
func (d *Deployment) Hash() string {
	sum := sha256.Sum256([]byte(d.Describe()))

	return hex.EncodeToString(sum[:8])
}
