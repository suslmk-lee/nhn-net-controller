package nhncloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client structures and methods

type Client struct {
	BaseURL    string
	HTTPClient *http.Client

	authURL  string
	tenantID string
	username string
	password string
	token    string
	tokenMu  sync.RWMutex
	tokenExp time.Time
}

func NewClient(baseURL, authURL, tenantID, username, password string) *Client {
	return &Client{
		BaseURL:  baseURL,
		authURL:  authURL,
		tenantID: tenantID,
		username: username,
		password: password,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// --- Authentication ---

type authRequest struct {
	Auth authRequestCredentials `json:"auth"`
}
type authRequestCredentials struct {
	TenantID            string              `json:"tenantId"`
	PasswordCredentials passwordCredentials `json:"passwordCredentials"`
}
type passwordCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type authResponse struct {
	Access access `json:"access"`
}
type access struct {
	Token token `json:"token"`
}
type token struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// --- LoadBalancer ---

type LoadBalancer struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	VipAddress         string `json:"vip_address"`
	VipSubnetID        string `json:"vip_subnet_id"`
	VipPortID          string `json:"vip_port_id"`
	ProvisioningStatus string `json:"provisioning_status"`
	Listeners          []struct {
		ID string `json:"id"`
	} `json:"listeners"`
}

type CreateLoadBalancerRequest struct {
	LoadBalancer CreateLoadBalancerSpec `json:"loadbalancer"`
}

type CreateLoadBalancerSpec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	VipSubnetID string `json:"vip_subnet_id"`
}

// --- Listener ---

type Listener struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	ProtocolPort  int    `json:"protocol_port"`
	DefaultPoolID string `json:"default_pool_id"`
}

type CreateListenerRequest struct {
	Listener CreateListenerSpec `json:"listener"`
}

type CreateListenerSpec struct {
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	ProtocolPort   int    `json:"protocol_port"`
	LoadbalancerID string `json:"loadbalancer_id"`
}

// --- Pool ---

type Pool struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	LbAlgorithm string   `json:"lb_algorithm"`
	Members     []Member `json:"members"`
}

type CreatePoolRequest struct {
	Pool CreatePoolSpec `json:"pool"`
}

type CreatePoolSpec struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	LbAlgorithm string `json:"lb_algorithm"`
	ListenerID  string `json:"listener_id"`
}

// --- Member ---

type Member struct {
	ID              string `json:"id"`
	Address         string `json:"address"`
	ProtocolPort    int    `json:"protocol_port"`
	OperatingStatus string `json:"operating_status"`
}

type CreateMemberRequest struct {
	Member CreateMemberSpec `json:"member"`
}

type CreateMemberSpec struct {
	Address      string `json:"address"`
	ProtocolPort int    `json:"protocol_port"`
}

// --- HealthMonitor ---

type HealthMonitor struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Delay      int    `json:"delay"`
	Timeout    int    `json:"timeout"`
	MaxRetries int    `json:"max_retries"`
	Pools      []struct {
		ID string `json:"id"`
	} `json:"pools"`
}

type CreateHealthMonitorRequest struct {
	HealthMonitor CreateHealthMonitorSpec `json:"healthmonitor"`
}

type CreateHealthMonitorSpec struct {
	Type       string `json:"type"`
	PoolID     string `json:"pool_id"`
	Delay      int    `json:"delay"`
	Timeout    int    `json:"timeout"`
	MaxRetries int    `json:"max_retries"`
}

// --- FloatingIP ---

type FloatingIP struct {
	ID                string `json:"id"`
	FloatingIPAddress string `json:"floating_ip_address"`
	PortID            string `json:"port_id"`
}

type CreateFloatingIPRequest struct {
	FloatingIP CreateFloatingIPSpec `json:"floatingip"`
}

type CreateFloatingIPSpec struct {
	FloatingNetworkID string `json:"floating_network_id"`
}

type UpdateFloatingIPRequest struct {
	FloatingIP UpdateFloatingIPSpec `json:"floatingip"`
}

type UpdateFloatingIPSpec struct {
	PortID *string `json:"port_id"`
}

// --- VPC ---

type VPC struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ExternalRouting bool   `json:"router:external"`
}

// --- Client Methods ---

func (c *Client) authenticate(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if time.Now().Before(c.tokenExp.Add(-1 * time.Minute)) {
		return nil
	}

	authReq := authRequest{
		Auth: authRequestCredentials{
			TenantID: c.tenantID,
			PasswordCredentials: passwordCredentials{
				Username: c.username,
				Password: c.password,
			},
		},
	}

	body, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.authURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.token = authResp.Access.Token.ID
	c.tokenExp = authResp.Access.Token.Expires

	return nil
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.tokenMu.RLock()
	if c.token != "" && time.Now().Before(c.tokenExp.Add(-1*time.Minute)) {
		defer c.tokenMu.RUnlock()
		return c.token, nil
	}
	c.tokenMu.RUnlock()

	return c.token, c.authenticate(ctx)
}

func (c *Client) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Auth-Token", token)

	return c.HTTPClient.Do(httpReq)
}

func (c *Client) GetLoadBalancer(ctx context.Context, loadBalancerID string) (*LoadBalancer, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/loadbalancers/%s", c.BaseURL, loadBalancerID)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Not found is not an error
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var lbResp struct {
		LoadBalancer LoadBalancer `json:"loadbalancer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lbResp); err != nil {
		return nil, err
	}
	return &lbResp.LoadBalancer, nil
}

func (c *Client) CreateLoadBalancer(ctx context.Context, req *CreateLoadBalancerRequest) (*LoadBalancer, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/loadbalancers", c.BaseURL)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var lbResp struct {
		LoadBalancer LoadBalancer `json:"loadbalancer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lbResp); err != nil {
		return nil, err
	}
	return &lbResp.LoadBalancer, nil
}

func (c *Client) DeleteLoadBalancer(ctx context.Context, loadBalancerID string) error {
	url := fmt.Sprintf("%s/v2.0/lbaas/loadbalancers/%s?cascade=true", c.BaseURL, loadBalancerID)
	resp, err := c.doRequest(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CreateListener(ctx context.Context, req *CreateListenerRequest) (*Listener, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/listeners", c.BaseURL)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return c.findListenerByName(ctx, req.Listener.Name)
	}
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var listenerResp struct {
		Listener Listener `json:"listener"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listenerResp); err != nil {
		return nil, err
	}
	return &listenerResp.Listener, nil
}

func (c *Client) findListenerByName(ctx context.Context, name string) (*Listener, error) {
	listeners, err := c.ListListeners(ctx)
	if err != nil {
		return nil, err
	}
	for _, listener := range listeners {
		if listener.Name == name {
			return &listener, nil
		}
	}
	return nil, fmt.Errorf("listener with name %s not found after conflict", name)
}

func (c *Client) ListListeners(ctx context.Context) ([]Listener, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/listeners", c.BaseURL)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var listResp struct {
		Listeners []Listener `json:"listeners"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}
	return listResp.Listeners, nil
}

func (c *Client) CreatePool(ctx context.Context, req *CreatePoolRequest) (*Pool, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/pools", c.BaseURL)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return c.findPoolByName(ctx, req.Pool.Name)
	}
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var poolResp struct {
		Pool Pool `json:"pool"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&poolResp); err != nil {
		return nil, err
	}
	return &poolResp.Pool, nil
}

func (c *Client) findPoolByName(ctx context.Context, name string) (*Pool, error) {
	pools, err := c.ListPools(ctx)
	if err != nil {
		return nil, err
	}
	for _, pool := range pools {
		if pool.Name == name {
			return &pool, nil
		}
	}
	return nil, fmt.Errorf("pool with name %s not found after conflict", name)
}

func (c *Client) ListPools(ctx context.Context) ([]Pool, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/pools", c.BaseURL)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var listResp struct {
		Pools []Pool `json:"pools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}
	return listResp.Pools, nil
}

func (c *Client) AddMemberToPool(ctx context.Context, poolID string, req *CreateMemberRequest) (*Member, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/pools/%s/members", c.BaseURL, poolID)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var memberResp struct {
		Member Member `json:"member"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&memberResp); err != nil {
		return nil, err
	}
	return &memberResp.Member, nil
}

func (c *Client) ListPoolMembers(ctx context.Context, poolID string) ([]Member, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/pools/%s/members", c.BaseURL, poolID)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var membersResp struct {
		Members []Member `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&membersResp); err != nil {
		return nil, err
	}
	return membersResp.Members, nil
}

func (c *Client) RemoveMemberFromPool(ctx context.Context, poolID, memberID string) error {
	url := fmt.Sprintf("%s/v2.0/lbaas/pools/%s/members/%s", c.BaseURL, poolID, memberID)
	resp, err := c.doRequest(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CreateHealthMonitor(ctx context.Context, req *CreateHealthMonitorRequest) (*HealthMonitor, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/healthmonitors", c.BaseURL)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return c.findHealthMonitorByPoolID(ctx, req.HealthMonitor.PoolID)
	}
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var hmResp struct {
		HealthMonitor HealthMonitor `json:"healthmonitor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hmResp); err != nil {
		return nil, err
	}
	return &hmResp.HealthMonitor, nil
}

func (c *Client) findHealthMonitorByPoolID(ctx context.Context, poolID string) (*HealthMonitor, error) {
	healthMonitors, err := c.ListHealthMonitors(ctx)
	if err != nil {
		return nil, err
	}
	for _, hm := range healthMonitors {
		if len(hm.Pools) > 0 && hm.Pools[0].ID == poolID {
			return &hm, nil
		}
	}
	return nil, fmt.Errorf("health monitor for pool %s not found after conflict", poolID)
}

func (c *Client) ListHealthMonitors(ctx context.Context) ([]HealthMonitor, error) {
	url := fmt.Sprintf("%s/v2.0/lbaas/healthmonitors", c.BaseURL)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var listResp struct {
		HealthMonitors []HealthMonitor `json:"healthmonitors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}
	return listResp.HealthMonitors, nil
}

func (c *Client) ListFloatingIPs(ctx context.Context) ([]FloatingIP, error) {
	url := fmt.Sprintf("%s/v2.0/floatingips", c.BaseURL)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var listResp struct {
		FloatingIPs []FloatingIP `json:"floatingips"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}
	return listResp.FloatingIPs, nil
}

func (c *Client) CreateFloatingIP(ctx context.Context, req *CreateFloatingIPRequest) (*FloatingIP, error) {
	url := fmt.Sprintf("%s/v2.0/floatingips", c.BaseURL)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var fipResp struct {
		FloatingIP FloatingIP `json:"floatingip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fipResp); err != nil {
		return nil, err
	}
	return &fipResp.FloatingIP, nil
}

func (c *Client) AssociateFloatingIP(ctx context.Context, fipID string, req *UpdateFloatingIPRequest) (*FloatingIP, error) {
	url := fmt.Sprintf("%s/v2.0/floatingips/%s", c.BaseURL, fipID)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var fipResp struct {
		FloatingIP FloatingIP `json:"floatingip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fipResp); err != nil {
		return nil, err
	}
	return &fipResp.FloatingIP, nil
}

func (c *Client) DisassociateFloatingIP(ctx context.Context, fipID string) (*FloatingIP, error) {
	req := &UpdateFloatingIPRequest{FloatingIP: UpdateFloatingIPSpec{PortID: nil}}
	return c.AssociateFloatingIP(ctx, fipID, req)
}

func (c *Client) GetFloatingIP(ctx context.Context, fipID string) (*FloatingIP, error) {
	url := fmt.Sprintf("%s/v2.0/floatingips/%s", c.BaseURL, fipID)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Not found is not an error
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var fipResp struct {
		FloatingIP FloatingIP `json:"floatingip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fipResp); err != nil {
		return nil, err
	}
	return &fipResp.FloatingIP, nil
}

func (c *Client) GetExternalNetworkID(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/v2.0/vpcs?router:external=true", c.BaseURL)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var vpcResp struct {
		VPCs []VPC `json:"vpcs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&vpcResp); err != nil {
		return "", err
	}

	if len(vpcResp.VPCs) == 0 {
		return "", fmt.Errorf("no external network found")
	}

	return vpcResp.VPCs[0].ID, nil
}
