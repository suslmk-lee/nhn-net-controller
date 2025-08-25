package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/suslmk-lee/kube-controller02/pkg/nhncloud"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultSecretConfig returns the default secret configuration
func DefaultSecretConfig() SecretConfig {
	return SecretConfig{
		Name: "nhncloud-credentials",
		Management: SecretManagement{
			Mode: "auto", // Default to auto-detection: OpenBao -> ESO -> Kubernetes
			OpenBao: OpenBaoConfig{
				Address:       "http://openbao.openbao-system.svc.cluster.local:8200",
				Path:          "secret/data/k-paas/nhn-controller",
				Role:          "nhn-controller",
				Namespace:     "openbao-system",
				AppRoleSecret: "cp-portal-secret",
			},
			ESO: ESOConfig{
				ExternalSecretName: "nhncloud-credentials-external",
				Timeout:            5 * time.Minute,
			},
		},
	}
}

// LoadConfigFromEnv loads secret configuration from environment variables
func LoadConfigFromEnv() SecretConfig {
	config := DefaultSecretConfig()

	// Override with environment variables if present
	if secretName := os.Getenv("SECRET_NAME"); secretName != "" {
		config.Name = secretName
	}

	if mode := os.Getenv("SECRET_MODE"); mode != "" {
		config.Management.Mode = mode
	}

	if address := os.Getenv("OPENBAO_ADDRESS"); address != "" {
		config.Management.OpenBao.Address = address
	}

	if path := os.Getenv("OPENBAO_PATH"); path != "" {
		config.Management.OpenBao.Path = path
	}

	if role := os.Getenv("OPENBAO_ROLE"); role != "" {
		config.Management.OpenBao.Role = role
	}

	if externalSecretName := os.Getenv("ESO_EXTERNAL_SECRET_NAME"); externalSecretName != "" {
		config.Management.ESO.ExternalSecretName = externalSecretName
	}

	if appRoleSecret := os.Getenv("OPENBAO_APPROLE_SECRET"); appRoleSecret != "" {
		config.Management.OpenBao.AppRoleSecret = appRoleSecret
	}

	return config
}

// Initialize creates NHN Cloud client with auto-detected secret backend
func Initialize(ctx context.Context, k8sClient client.Client, namespace string) (*nhncloud.Client, error) {
	logger := log.FromContext(ctx)

	// Load configuration
	config := LoadConfigFromEnv()

	// Create secret detector for auto-detection
	detector := NewSecretDetector(k8sClient, config, namespace)

	// Get credentials using auto-detection (OpenBao -> ESO -> Secret)
	creds, err := detector.GetCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize credentials: %w", err)
	}

	logger.Info("Credentials successfully retrieved with auto-detection")

	// Create NHN Cloud client
	nhnClient := nhncloud.NewClient(
		creds.APIBaseURL,
		creds.AuthURL,
		creds.TenantID,
		creds.Username,
		creds.Password,
	)

	logger.Info("NHN Cloud client initialized successfully")
	return nhnClient, nil
}
