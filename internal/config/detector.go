package config

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ProviderCredentials holds NHN Cloud credentials
type ProviderCredentials struct {
	APIBaseURL  string
	AuthURL     string
	TenantID    string
	Username    string
	Password    string
	VIPSubnetID string
}

// SecretDetector handles backend detection and credential retrieval
type SecretDetector struct {
	client    client.Client
	config    SecretConfig
	namespace string
}

// NewSecretDetector creates a new SecretDetector
func NewSecretDetector(client client.Client, config SecretConfig, namespace string) *SecretDetector {
	return &SecretDetector{
		client:    client,
		config:    config,
		namespace: namespace,
	}
}

// DetectBackend determines which secret backend to use
func (d *SecretDetector) DetectBackend(ctx context.Context) (SecretBackend, error) {
	logger := log.FromContext(ctx)

	// If mode is explicitly set, respect it (except for auto)
	switch d.config.Management.Mode {
	case "openbao":
		return BackendOpenBao, nil
	case "eso":
		return BackendESO, nil
	case "kubernetes":
		return BackendKubernetes, nil
	case "auto":
		// Continue with auto-detection
		break
	default:
		logger.Info("Unknown mode, defaulting to auto-detection", "mode", d.config.Management.Mode)
	}

	// Auto-detection: OpenBao -> ESO -> Kubernetes
	logger.Info("Auto-detecting secret backend...")

	// 1. Check for OpenBao
	if d.checkOpenBaoAvailability(ctx) {
		logger.Info("OpenBao detected, using OpenBao backend")
		return BackendOpenBao, nil
	}

	// 2. Check for External Secrets Operator
	if d.checkESOAvailability(ctx) {
		logger.Info("External Secrets Operator detected, using ESO backend")
		return BackendESO, nil
	}

	// 3. Fallback to Kubernetes Secret
	logger.Info("No external secret backends found, using Kubernetes Secret")
	return BackendKubernetes, nil
}

// checkOpenBaoAvailability checks if OpenBao is available
func (d *SecretDetector) checkOpenBaoAvailability(ctx context.Context) bool {
	// Check for OpenBao CRD
	openbaoGVR := schema.GroupVersionResource{
		Group:    "openbao.openbao.org",
		Version:  "v1alpha1",
		Resource: "vaults",
	}

	if !d.checkCRDExists(ctx, openbaoGVR) {
		return false
	}

	// Check for OpenBao service
	return d.checkServiceExists(ctx, "openbao", d.config.Management.OpenBao.Namespace)
}

// checkESOAvailability checks if External Secrets Operator is available
func (d *SecretDetector) checkESOAvailability(ctx context.Context) bool {
	// Check for ESO CRDs
	secretStoreGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "secretstores",
	}

	externalSecretGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1beta1",
		Resource: "externalsecrets",
	}

	return d.checkCRDExists(ctx, secretStoreGVR) && d.checkCRDExists(ctx, externalSecretGVR)
}

// checkServiceExists verifies if a Kubernetes service exists
func (d *SecretDetector) checkServiceExists(ctx context.Context, name, namespace string) bool {
	logger := log.FromContext(ctx)

	var service corev1.Service
	key := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}

	err := d.client.Get(ctx, key, &service)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.V(1).Info("Error checking service existence", "service", name, "namespace", namespace, "error", err)
		}
		return false
	}

	logger.V(1).Info("Service detected", "service", name, "namespace", namespace)
	return true
}

// checkCRDExists verifies if a Custom Resource Definition exists
func (d *SecretDetector) checkCRDExists(ctx context.Context, gvr schema.GroupVersionResource) bool {
	logger := log.FromContext(ctx)

	var crd apiextv1.CustomResourceDefinition
	crdName := fmt.Sprintf("%s.%s", gvr.Resource, gvr.Group)

	key := types.NamespacedName{
		Name: crdName,
	}

	err := d.client.Get(ctx, key, &crd)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.V(1).Info("Error checking CRD existence", "crd", crdName, "error", err)
		}
		return false
	}

	logger.V(1).Info("CRD detected", "crd", crdName)
	return true
}

// GetCredentials retrieves credentials from the determined backend
func (d *SecretDetector) GetCredentials(ctx context.Context) (*ProviderCredentials, error) {
	logger := log.FromContext(ctx)

	backendType, err := d.DetectBackend(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect secret backend: %w", err)
	}

	logger.Info("Secret backend detected", "backend", string(backendType))

	switch backendType {
	case BackendOpenBao:
		logger.Info("Using OpenBao for sensitive credentials")
		return d.getCredentialsFromOpenBao(ctx)
	case BackendESO:
		logger.Info("Using External Secrets Operator for sensitive credentials")
		return d.getCredentialsFromESO(ctx)
	case BackendKubernetes:
		logger.Info("Using Kubernetes Secret for sensitive credentials")
		return d.getCredentialsFromKubernetes(ctx)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s", backendType)
	}
}

// getCredentialsFromKubernetes retrieves credentials from Kubernetes secret + ConfigMap
func (d *SecretDetector) getCredentialsFromKubernetes(ctx context.Context) (*ProviderCredentials, error) {
	logger := log.FromContext(ctx)
	logger.Info("Retrieving sensitive credentials from Kubernetes Secret", "secretName", d.config.Name)

	creds := &ProviderCredentials{}

	// 1. Get sensitive info from Secret
	var secret corev1.Secret
	namespace := d.namespace
	if d.config.Management.Kubernetes.Namespace != "" {
		namespace = d.config.Management.Kubernetes.Namespace
	}

	secretKey := types.NamespacedName{
		Name:      d.config.Name,
		Namespace: namespace,
	}

	err := d.client.Get(ctx, secretKey, &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, d.config.Name, err)
	}

	// Extract sensitive credentials from secret
	creds.TenantID = string(secret.Data["NHN_TENANT_ID"])
	creds.Username = string(secret.Data["NHN_USERNAME"])
	creds.Password = string(secret.Data["NHN_PASSWORD"])

	// 2. Get public config from ConfigMap
	if err := d.getPublicConfigFromConfigMap(ctx, creds); err != nil {
		return nil, err
	}

	// Validate required fields
	if err := d.validateCredentials(creds); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	return creds, nil
}

// getCredentialsFromESO retrieves credentials managed by External Secrets Operator
func (d *SecretDetector) getCredentialsFromESO(ctx context.Context) (*ProviderCredentials, error) {
	logger := log.FromContext(ctx)

	// First wait for ExternalSecret to be ready
	if d.config.Management.ESO.ExternalSecretName != "" {
		logger.Info("Waiting for ExternalSecret to be ready", "externalSecret", d.config.Management.ESO.ExternalSecretName)

		if err := d.waitForExternalSecret(ctx); err != nil {
			return nil, fmt.Errorf("ExternalSecret not ready: %w", err)
		}
	}

	// Once ESO is ready, read the generated Kubernetes secret (sensitive data only)
	logger.Info("ExternalSecret ready, reading generated secret for sensitive credentials")
	return d.getCredentialsFromKubernetes(ctx)
}

// getCredentialsFromOpenBao retrieves credentials from OpenBao
func (d *SecretDetector) getCredentialsFromOpenBao(ctx context.Context) (*ProviderCredentials, error) {
	logger := log.FromContext(ctx)
	logger.Info("Retrieving sensitive credentials from OpenBao", "address", d.config.Management.OpenBao.Address)

	// TODO: Implement OpenBao client integration
	// This would involve:
	// 1. Initialize OpenBao client
	// 2. Authenticate using Kubernetes service account
	// 3. Read secret from specified path (sensitive data only)
	// 4. Get public config from ConfigMap

	return nil, fmt.Errorf("OpenBao integration not yet implemented")
}

// getPublicConfigFromConfigMap retrieves public configuration from ConfigMap
func (d *SecretDetector) getPublicConfigFromConfigMap(ctx context.Context, creds *ProviderCredentials) error {
	logger := log.FromContext(ctx)

	configMapName := "nhncloud-config" // Fixed ConfigMap name for public settings

	var configMap corev1.ConfigMap
	configKey := types.NamespacedName{
		Name:      configMapName,
		Namespace: d.namespace,
	}

	if err := d.client.Get(ctx, configKey, &configMap); err != nil {
		logger.Info("ConfigMap not found, using defaults", "configMap", configMapName)
		// Use defaults for public config
		creds.APIBaseURL = "https://kr1-api-network-infrastructure.nhncloudservice.com"
		creds.AuthURL = "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens"
		creds.VIPSubnetID = "" // This should be set in ConfigMap
		return nil
	}

	// Extract public configuration from ConfigMap
	creds.APIBaseURL = configMap.Data["NHN_API_BASE_URL"]
	creds.AuthURL = configMap.Data["NHN_AUTH_URL"]
	creds.VIPSubnetID = configMap.Data["NHN_VIP_SUBNET_ID"]

	return nil
}

// waitForExternalSecret waits for ExternalSecret to be ready
func (d *SecretDetector) waitForExternalSecret(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// TODO: Implement ExternalSecret status monitoring
	// This would involve:
	// 1. Get ExternalSecret resource
	// 2. Check status.conditions for Ready condition
	// 3. Wait/retry until ready or timeout

	logger.Info("ExternalSecret monitoring not yet implemented")
	return nil
}

// validateCredentials ensures all required credential fields are present
func (d *SecretDetector) validateCredentials(creds *ProviderCredentials) error {
	if creds.APIBaseURL == "" {
		return fmt.Errorf("NHN_API_BASE_URL is required")
	}
	if creds.AuthURL == "" {
		return fmt.Errorf("NHN_AUTH_URL is required")
	}
	if creds.TenantID == "" {
		return fmt.Errorf("NHN_TENANT_ID is required")
	}
	if creds.Username == "" {
		return fmt.Errorf("NHN_USERNAME is required")
	}
	if creds.Password == "" {
		return fmt.Errorf("NHN_PASSWORD is required")
	}
	if creds.VIPSubnetID == "" {
		return fmt.Errorf("NHN_VIP_SUBNET_ID is required")
	}

	return nil
}
