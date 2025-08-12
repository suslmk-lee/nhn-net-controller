package config

import (
	"time"
)

// SecretBackend represents available secret backends
type SecretBackend string

const (
	BackendOpenBao    SecretBackend = "openbao"
	BackendESO        SecretBackend = "eso"
	BackendKubernetes SecretBackend = "kubernetes"
)

// SecretConfig defines secret management configuration
type SecretConfig struct {
	Name       string           `yaml:"name"`
	Management SecretManagement `yaml:"management"`
}

// SecretManagement defines how secrets are managed
type SecretManagement struct {
	Mode       string           `yaml:"mode"` // auto, openbao, eso, kubernetes
	OpenBao    OpenBaoConfig    `yaml:"openbao"`
	ESO        ESOConfig        `yaml:"eso"`
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
}

// OpenBaoConfig defines OpenBao specific configuration
type OpenBaoConfig struct {
	Address   string `yaml:"address"`
	Path      string `yaml:"path"`
	Role      string `yaml:"role"`
	Namespace string `yaml:"namespace"`
}

// ESOConfig defines External Secrets Operator configuration
type ESOConfig struct {
	ExternalSecretName string        `yaml:"externalSecretName"`
	SecretStoreName    string        `yaml:"secretStoreName"`
	Timeout            time.Duration `yaml:"timeout"`
}

// KubernetesConfig defines Kubernetes Secret configuration
type KubernetesConfig struct {
	Namespace string `yaml:"namespace"`
}
