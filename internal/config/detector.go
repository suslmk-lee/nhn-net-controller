package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

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

// AppRoleAuthRequest represents OpenBao AppRole authentication request
type AppRoleAuthRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id,omitempty"`
}

// AppRoleAuthResponse represents OpenBao AppRole authentication response
type AppRoleAuthResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		Accessor      string `json:"accessor"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

// OpenBaoSecretResponse represents secret data from OpenBao
type OpenBaoSecretResponse struct {
	Data struct {
		Data map[string]interface{} `json:"data"`
	} `json:"data"`
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
	logger.Info("Retrieving sensitive credentials from OpenBao using AppRole", "address", d.config.Management.OpenBao.Address)

	// 1. Get AppRole credentials from cp-portal-secret
	roleID, roleName, err := d.getAppRoleCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get AppRole credentials: %w", err)
	}

	// 2. Authenticate with OpenBao using AppRole
	token, err := d.authenticateWithOpenBao(ctx, roleID, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with OpenBao: %w", err)
	}

	// 3. Retrieve NHN credentials from OpenBao
	creds, err := d.retrieveCredentialsFromOpenBao(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials from OpenBao: %w", err)
	}

	// 4. Get public config from ConfigMap
	if err := d.getPublicConfigFromConfigMap(ctx, creds); err != nil {
		return nil, err
	}

	// 5. Validate required fields
	if err := d.validateCredentials(creds); err != nil {
		return nil, fmt.Errorf("invalid credentials from OpenBao: %w", err)
	}

	return creds, nil
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
		logger.Info("ConfigMap not found, using environment variables", "configMap", configMapName)
		// Use environment variables when ConfigMap is not available
		creds.APIBaseURL = getEnvOrDefault("NHN_API_BASE_URL", "https://kr1-api-network-infrastructure.nhncloudservice.com")
		creds.AuthURL = getEnvOrDefault("NHN_AUTH_URL", "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens")
		creds.VIPSubnetID = getEnvOrDefault("NHN_VIP_SUBNET_ID", "7b027099-273f-4992-a8f4-f1f95371d196") // Default subnet
		return nil
	}

	// ConfigMap found - use ConfigMap values with environment variable override
	creds.APIBaseURL = getValueOrDefault(configMap.Data["NHN_API_BASE_URL"], "NHN_API_BASE_URL", "https://kr1-api-network-infrastructure.nhncloudservice.com")
	creds.AuthURL = getValueOrDefault(configMap.Data["NHN_AUTH_URL"], "NHN_AUTH_URL", "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens")
	creds.VIPSubnetID = getValueOrDefault(configMap.Data["NHN_VIP_SUBNET_ID"], "NHN_VIP_SUBNET_ID", "7b027099-273f-4992-a8f4-f1f95371d196")

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

// getAppRoleCredentials retrieves VAULT_ROLE_ID and VAULT_ROLE_NAME from configured secret
func (d *SecretDetector) getAppRoleCredentials(ctx context.Context) (roleID, roleName string, err error) {
	logger := log.FromContext(ctx)
	logger.Info("Retrieving AppRole credentials from secret")

	var secret corev1.Secret
	secretName := d.config.Management.OpenBao.AppRoleSecret
	if secretName == "" {
		secretName = "cp-portal-secret" // Fallback to default name
	}

	secretKey := types.NamespacedName{
		Name:      secretName,
		Namespace: d.namespace,
	}

	if err := d.client.Get(ctx, secretKey, &secret); err != nil {
		return "", "", fmt.Errorf("failed to get AppRole secret %s: %w", secretName, err)
	}

	roleID = string(secret.Data["VAULT_ROLE_ID"])
	roleName = string(secret.Data["VAULT_ROLE_NAME"])

	if roleID == "" {
		return "", "", fmt.Errorf("VAULT_ROLE_ID not found in secret %s", secretName)
	}
	if roleName == "" {
		return "", "", fmt.Errorf("VAULT_ROLE_NAME not found in secret %s", secretName)
	}

	logger.Info("Successfully retrieved AppRole credentials", "roleName", roleName)
	return roleID, roleName, nil
}

// authenticateWithOpenBao authenticates with OpenBao using AppRole
func (d *SecretDetector) authenticateWithOpenBao(ctx context.Context, roleID, roleName string) (string, error) {
	logger := log.FromContext(ctx)
	logger.Info("Authenticating with OpenBao using AppRole", "roleName", roleName)

	// For AppRole authentication without secret_id (if configured for no secret_id)
	authReq := AppRoleAuthRequest{
		RoleID: roleID,
	}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth request: %w", err)
	}

	// Make authentication request to OpenBao
	authURL := fmt.Sprintf("%s/v1/auth/approle/login", d.config.Management.OpenBao.Address)
	req, err := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate with OpenBao: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var authResp AppRoleAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	if authResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("no client token received from OpenBao")
	}

	logger.Info("Successfully authenticated with OpenBao")
	return authResp.Auth.ClientToken, nil
}

// retrieveCredentialsFromOpenBao retrieves NHN credentials from OpenBao using the token
func (d *SecretDetector) retrieveCredentialsFromOpenBao(ctx context.Context, token string) (*ProviderCredentials, error) {
	logger := log.FromContext(ctx)
	logger.Info("Retrieving NHN credentials from OpenBao", "path", d.config.Management.OpenBao.Path)

	// Make request to retrieve secret from OpenBao
	secretURL := fmt.Sprintf("%s/v1/%s", d.config.Management.OpenBao.Address, d.config.Management.OpenBao.Path)
	req, err := http.NewRequestWithContext(ctx, "GET", secretURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret request: %w", err)
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret from OpenBao: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("secret retrieval failed, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var secretResp OpenBaoSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("failed to decode secret response: %w", err)
	}

	// Extract NHN credentials from secret data
	data := secretResp.Data.Data

	creds := &ProviderCredentials{}

	if tenantID, ok := data["NHN_TENANT_ID"].(string); ok {
		creds.TenantID = tenantID
	}
	if username, ok := data["NHN_USERNAME"].(string); ok {
		creds.Username = username
	}
	if password, ok := data["NHN_PASSWORD"].(string); ok {
		creds.Password = password
	}

	logger.Info("Successfully retrieved NHN credentials from OpenBao")
	return creds, nil
}

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getValueOrDefault returns value with priority: env var > configmap value > default
func getValueOrDefault(configValue, envKey, defaultValue string) string {
	// 1st priority: Environment variable
	if envValue := os.Getenv(envKey); envValue != "" {
		return envValue
	}
	// 2nd priority: ConfigMap value
	if configValue != "" {
		return configValue
	}
	// 3rd priority: Default value
	return defaultValue
}
