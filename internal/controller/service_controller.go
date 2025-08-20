package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/suslmk-lee/kube-controller02/pkg/nhncloud"
)

const (
	finalizerName             = "nhn.cloud/load-balancer-finalizer"
	requeueDelay              = 20 * time.Second
	lbIDAnnotation            = "nhn.cloud/load-balancer-id"
	floatingIPIDAnnotation    = "nhn.cloud/floating-ip-id"
	controllerAnnotation      = "nhn.cloud/managed-by"
	controllerAnnotationValue = "nhn-cloud-controller"
	portStatusAnnotation      = "nhn.cloud/port-status"
)

// PortStatus tracks the reconciliation status of each port
type PortStatus struct {
	Port           int32  `json:"port"`
	Protocol       string `json:"protocol"`
	Status         string `json:"status"` // pending, active, failed
	ListenerID     string `json:"listenerId,omitempty"`
	PoolID         string `json:"poolId,omitempty"`
	LastReconciled string `json:"lastReconciled,omitempty"`
}

type ServiceReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	NHNClient *nhncloud.Client
}

//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=services/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list
//+kubebuilder:rbac:groups=external-secrets.io,resources=secretstores,verbs=get;list
//+kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=openbao.openbao.org,resources=vaults,verbs=get;list
//+kubebuilder:rbac:groups=openbao.openbao.org,resources=vaultconnections,verbs=get;list

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var service corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &service); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return ctrl.Result{}, nil
	}

	// Check if this service should be managed by our controller
	if !r.shouldManageService(&service) {
		return ctrl.Result{}, nil
	}

	if !service.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleServiceDeletion(ctx, &service)
	}

	return r.reconcileLoadBalancer(ctx, &service)
}

// shouldManageService checks if this service should be managed by our controller
func (r *ServiceReconciler) shouldManageService(service *corev1.Service) bool {
	var controllerValue string
	if service.Annotations != nil {
		controllerValue = service.Annotations[controllerAnnotation]
	}
	return controllerValue == "" || controllerValue == controllerAnnotationValue
}

// clearConflictingIP clears IP addresses set by other controllers
func (r *ServiceReconciler) clearConflictingIP(ctx context.Context, service *corev1.Service) (ctrl.Result, bool) {
	if service.Status.LoadBalancer.Ingress == nil || len(service.Status.LoadBalancer.Ingress) == 0 {
		return ctrl.Result{}, false
	}

	currentIP := service.Status.LoadBalancer.Ingress[0].IP
	fipID := ""
	if service.Annotations != nil {
		fipID = service.Annotations[floatingIPIDAnnotation]
	}

	// If we have a floating IP annotation, verify it matches current IP
	if fipID != "" {
		floatingIP, err := r.NHNClient.GetFloatingIP(ctx, fipID)
		if err == nil && floatingIP != nil && floatingIP.FloatingIPAddress == currentIP {
			return ctrl.Result{}, false // Keep our IP
		}
	}

	// Clear conflicting IP
	service.Status.LoadBalancer.Ingress = nil
	if err := r.Status().Update(ctx, service); err != nil {
		return ctrl.Result{}, true
	}
	return ctrl.Result{Requeue: true}, true
}

// ensureServiceMetadata adds finalizer and controller annotation to service
func (r *ServiceReconciler) ensureServiceMetadata(ctx context.Context, service *corev1.Service) error {
	patch := client.MergeFrom(service.DeepCopy())
	needsUpdate := false

	if !controllerutil.ContainsFinalizer(service, finalizerName) {
		controllerutil.AddFinalizer(service, finalizerName)
		needsUpdate = true
	}

	if service.Annotations == nil {
		service.Annotations = make(map[string]string)
	}
	if service.Annotations[controllerAnnotation] != controllerAnnotationValue {
		service.Annotations[controllerAnnotation] = controllerAnnotationValue
		needsUpdate = true
	}

	if needsUpdate {
		return r.Patch(ctx, service, patch)
	}
	return nil
}

func (r *ServiceReconciler) reconcileLoadBalancer(ctx context.Context, service *corev1.Service) (ctrl.Result, error) {
	if service == nil {
		return ctrl.Result{}, fmt.Errorf("service is nil")
	}

	// Clear conflicting ingress IPs from other controllers
	if result, shouldReturn := r.clearConflictingIP(ctx, service); shouldReturn {
		return result, nil
	}

	// Ensure service has proper finalizer and annotations
	if err := r.ensureServiceMetadata(ctx, service); err != nil {
		return ctrl.Result{}, err
	}

	lb, err := r.ensureLoadBalancer(ctx, service)
	if err != nil {
		return ctrl.Result{}, err
	}
	if lb == nil {
		return ctrl.Result{}, fmt.Errorf("load balancer is nil after ensure")
	}

	// Check if all resources are ready and update status if they are.
	return r.checkAndUpdateStatus(ctx, service, lb)
}

func (r *ServiceReconciler) checkAndUpdateStatus(ctx context.Context, service *corev1.Service, lb *nhncloud.LoadBalancer) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Add nil safety checks
	if service == nil {
		return ctrl.Result{}, fmt.Errorf("service is nil")
	}
	if lb == nil {
		return ctrl.Result{}, fmt.Errorf("load balancer is nil")
	}

	// 1. Wait for Load Balancer to be ACTIVE
	result, activeLB, err := r.waitForLoadBalancerActive(ctx, lb.ID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	// 2. Reconcile all sub-resources (Listener, Pool, HealthMonitor, Members)
	result, err = r.reconcileSubResources(ctx, service, activeLB)
	if err != nil {
		logger.Error(err, "Failed to reconcile sub-resources, will retry", "lbID", activeLB.ID)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	// 3. Ensure Floating IP is associated
	floatingIP, err := r.ensureFloatingIP(ctx, service, activeLB)
	if err != nil {
		return ctrl.Result{}, err
	}
	if floatingIP == nil {
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}
	if floatingIP.PortID == "" {
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	// All ready, update the service status with the Floating IP
	logger.Info("LoadBalancer ready, assigning public IP", "service", service.Name, "ip", floatingIP.FloatingIPAddress)
	return r.updateServiceStatus(ctx, service, floatingIP.FloatingIPAddress)
}

func (r *ServiceReconciler) ensureLoadBalancer(ctx context.Context, service *corev1.Service) (*nhncloud.LoadBalancer, error) {
	var lbID string
	if service.Annotations != nil {
		lbID = service.Annotations[lbIDAnnotation]
	}
	if lbID != "" {
		lb, err := r.NHNClient.GetLoadBalancer(ctx, lbID)
		if err != nil {
			return nil, err
		}
		if lb == nil {
			// Load balancer doesn't exist, create new one
			// Fall through to create new load balancer
		} else {
			return lb, nil
		}
	}

	lbName := fmt.Sprintf("k8s-%s-%s-%s", service.Namespace, service.Name, service.UID[:8])
	req := &nhncloud.CreateLoadBalancerRequest{
		LoadBalancer: nhncloud.CreateLoadBalancerSpec{
			Name:        lbName,
			Description: fmt.Sprintf("Load balancer for Kubernetes service %s/%s", service.Namespace, service.Name),
			VipSubnetID: os.Getenv("NHN_VIP_SUBNET_ID"),
		},
	}
	newLB, err := r.NHNClient.CreateLoadBalancer(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := r.updateServiceAnnotation(ctx, service, lbIDAnnotation, newLB.ID); err != nil {
		return nil, err
	}
	return newLB, nil
}

func (r *ServiceReconciler) reconcileSubResources(ctx context.Context, service *corev1.Service, lb *nhncloud.LoadBalancer) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// First ensure load balancer is in ACTIVE state before making any changes
	if lb.ProvisioningStatus != "ACTIVE" {
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	var needsRequeue bool
	var requeueAfter time.Duration

	for _, port := range service.Spec.Ports {
		// Skip ports that are already completed
		if r.isPortCompleted(service, port) {
			logger.V(1).Info("Port already completed, skipping", "port", port.Port, "protocol", port.Protocol)
			continue
		}

		logger.Info("Processing port", "port", port.Port, "protocol", port.Protocol)
		result, err := r.reconcilePort(ctx, lb.ID, port, service)
		if err != nil {
			logger.Error(err, "Failed to reconcile port, continuing with other ports", "port", port.Port)
			// Mark port as failed
			if updateErr := r.updatePortStatus(ctx, service, port, "failed", "", ""); updateErr != nil {
				logger.Error(updateErr, "Failed to update port status", "port", port.Port)
			}
			needsRequeue = true
			if requeueAfter == 0 || (result.RequeueAfter > 0 && result.RequeueAfter < requeueAfter) {
				requeueAfter = requeueDelay
			}
			continue // Continue processing other ports
		}
		if result.Requeue || result.RequeueAfter > 0 {
			logger.Info("Port needs requeue, continuing with other ports", "port", port.Port, "requeueAfter", result.RequeueAfter)
			// Mark port as pending
			if updateErr := r.updatePortStatus(ctx, service, port, "pending", "", ""); updateErr != nil {
				logger.Error(updateErr, "Failed to update port status", "port", port.Port)
			}
			needsRequeue = true
			if requeueAfter == 0 || (result.RequeueAfter > 0 && result.RequeueAfter < requeueAfter) {
				requeueAfter = result.RequeueAfter
			}
			continue // Continue processing other ports
		}
		logger.Info("Port reconciled successfully", "port", port.Port)
	}

	// Only requeue if at least one port needs it
	if needsRequeue {
		if requeueAfter > 0 {
			return ctrl.Result{RequeueAfter: requeueAfter}, nil
		}
		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) reconcilePort(ctx context.Context, lbID string, port corev1.ServicePort, service *corev1.Service) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	result, lb, err := r.waitForLoadBalancerActive(ctx, lbID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	// Check if listener already exists before creating
	listener, err := r.ensureListener(ctx, lb, port)
	if err != nil {
		logger.Error(err, "Failed to ensure listener", "port", port.Port)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	// Wait for LB to be active after listener creation/update
	result, _, err = r.waitForLoadBalancerActive(ctx, lbID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	// Check if pool already exists before creating
	pool, err := r.ensurePool(ctx, listener)
	if err != nil {
		logger.Error(err, "Failed to ensure pool", "listenerID", listener.ID)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	// Wait for LB to be active after pool creation/update
	result, _, err = r.waitForLoadBalancerActive(ctx, lbID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	if err := r.ensureHealthMonitor(ctx, pool); err != nil {
		logger.Error(err, "Failed to ensure health monitor", "poolID", pool.ID)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	// Wait for LB to be active after health monitor creation/update
	result, _, err = r.waitForLoadBalancerActive(ctx, lbID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	if err := r.reconcileMembers(ctx, pool, port.NodePort); err != nil {
		logger.Error(err, "Failed to reconcile members", "poolID", pool.ID)
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	result, err = r.waitForPoolMembersOnline(ctx, pool.ID)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.Requeue || result.RequeueAfter > 0 {
		return result, nil
	}

	// Port is now fully reconciled - update status as active
	if updateErr := r.updatePortStatus(ctx, service, port, "active", listener.ID, pool.ID); updateErr != nil {
		logger.Error(updateErr, "Failed to update port status to active", "port", port.Port)
		// Don't fail the reconciliation for status update errors
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) waitForLoadBalancerActive(ctx context.Context, lbID string) (ctrl.Result, *nhncloud.LoadBalancer, error) {
	lb, err := r.NHNClient.GetLoadBalancer(ctx, lbID)
	if err != nil {
		return ctrl.Result{}, nil, err
	}
	if lb.ProvisioningStatus == "ACTIVE" {
		return ctrl.Result{}, lb, nil
	}
	if lb.ProvisioningStatus == "ERROR" {
		return ctrl.Result{}, nil, fmt.Errorf("load balancer %s is in ERROR state", lbID)
	}
	return ctrl.Result{RequeueAfter: requeueDelay}, nil, nil
}

func (r *ServiceReconciler) ensureListener(ctx context.Context, lb *nhncloud.LoadBalancer, port corev1.ServicePort) (*nhncloud.Listener, error) {
	// Double-check load balancer state before making API calls
	if lb.ProvisioningStatus != "ACTIVE" {
		return nil, fmt.Errorf("load balancer %s is not active (status: %s), cannot create listener", lb.ID, lb.ProvisioningStatus)
	}

	// Check if listener already exists for this port by name pattern
	expectedName := fmt.Sprintf("listener-%s-%d", lb.ID, port.Port)
	listeners, err := r.NHNClient.ListListeners(ctx)
	if err == nil {
		for _, listener := range listeners {
			if listener.Name == expectedName && listener.ProtocolPort == int(port.Port) && listener.Protocol == string(port.Protocol) {
				return &listener, nil
			}
		}
	}

	// Create new listener
	req := &nhncloud.CreateListenerRequest{
		Listener: nhncloud.CreateListenerSpec{
			Name:           expectedName,
			Protocol:       string(port.Protocol),
			ProtocolPort:   int(port.Port),
			LoadbalancerID: lb.ID,
		},
	}
	return r.NHNClient.CreateListener(ctx, req)
}

func (r *ServiceReconciler) ensurePool(ctx context.Context, listener *nhncloud.Listener) (*nhncloud.Pool, error) {
	// Check if pool already exists for this listener by name pattern
	expectedName := fmt.Sprintf("pool-%s", listener.ID)
	pools, err := r.NHNClient.ListPools(ctx)
	if err == nil {
		for _, pool := range pools {
			if pool.Name == expectedName {
				return &pool, nil
			}
		}
	}

	// Create new pool
	req := &nhncloud.CreatePoolRequest{
		Pool: nhncloud.CreatePoolSpec{
			Name:        expectedName,
			Protocol:    listener.Protocol,
			LbAlgorithm: "ROUND_ROBIN",
			ListenerID:  listener.ID,
		},
	}
	return r.NHNClient.CreatePool(ctx, req)
}

func (r *ServiceReconciler) ensureHealthMonitor(ctx context.Context, pool *nhncloud.Pool) error {
	healthMonitors, err := r.NHNClient.ListHealthMonitors(ctx)
	if err != nil {
		return err
	}
	for _, hm := range healthMonitors {
		for _, p := range hm.Pools {
			if p.ID == pool.ID {
				return nil
			}
		}
	}

	req := &nhncloud.CreateHealthMonitorRequest{
		HealthMonitor: nhncloud.CreateHealthMonitorSpec{
			Type:       "TCP",
			PoolID:     pool.ID,
			Delay:      10,
			Timeout:    5,
			MaxRetries: 3,
		},
	}
	_, err = r.NHNClient.CreateHealthMonitor(ctx, req)
	return err
}

func (r *ServiceReconciler) reconcileMembers(ctx context.Context, pool *nhncloud.Pool, nodePort int32) error {
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return err
	}

	cloudMembers, err := r.NHNClient.ListPoolMembers(ctx, pool.ID)
	if err != nil {
		return err
	}

	cloudMemberMap := make(map[string]nhncloud.Member)
	for _, member := range cloudMembers {
		cloudMemberMap[member.Address] = member
	}

	for _, node := range nodes.Items {
		nodeIP := ""
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nodeIP = addr.Address
				break
			}
		}
		if nodeIP == "" {
			continue
		}

		if _, exists := cloudMemberMap[nodeIP]; !exists {
			memberReq := &nhncloud.CreateMemberRequest{
				Member: nhncloud.CreateMemberSpec{
					Address:      nodeIP,
					ProtocolPort: int(nodePort),
				},
			}
			if _, err := r.NHNClient.AddMemberToPool(ctx, pool.ID, memberReq); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *ServiceReconciler) waitForPoolMembersOnline(ctx context.Context, poolID string) (ctrl.Result, error) {
	members, err := r.NHNClient.ListPoolMembers(ctx, poolID)
	if err != nil {
		return ctrl.Result{}, err
	}

	onlineCount := 0
	for _, member := range members {
		// Accept both ONLINE and ACTIVE as valid operational states
		if member.OperatingStatus == "ONLINE" || member.OperatingStatus == "ACTIVE" {
			onlineCount++
		}
	}

	// If at least one member is online, proceed (for better resilience)
	if onlineCount > 0 {
		return ctrl.Result{}, nil
	}

	// If no members are online, continue waiting
	if len(members) > 0 {
		return ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) ensureFloatingIP(ctx context.Context, service *corev1.Service, lb *nhncloud.LoadBalancer) (*nhncloud.FloatingIP, error) {
	var fipID string
	if service.Annotations != nil {
		fipID = service.Annotations[floatingIPIDAnnotation]
	}
	if fipID != "" {
		return r.NHNClient.GetFloatingIP(ctx, fipID)
	}

	floatingNetworkID, err := r.NHNClient.GetExternalNetworkID(ctx)
	if err != nil {
		return nil, err
	}

	req := &nhncloud.CreateFloatingIPRequest{
		FloatingIP: nhncloud.CreateFloatingIPSpec{
			FloatingNetworkID: floatingNetworkID,
		},
	}
	newFIP, err := r.NHNClient.CreateFloatingIP(ctx, req)
	if err != nil {
		return nil, err
	}

	assocReq := &nhncloud.UpdateFloatingIPRequest{
		FloatingIP: nhncloud.UpdateFloatingIPSpec{
			PortID: &lb.VipPortID,
		},
	}
	associatedFIP, err := r.NHNClient.AssociateFloatingIP(ctx, newFIP.ID, assocReq)
	if err != nil {
		return nil, err
	}

	if err := r.updateServiceAnnotation(ctx, service, floatingIPIDAnnotation, associatedFIP.ID); err != nil {
		return nil, err
	}

	return associatedFIP, nil
}

func (r *ServiceReconciler) handleServiceDeletion(ctx context.Context, service *corev1.Service) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(service, finalizerName) {
		var lbID, fipID string
		if service.Annotations != nil {
			lbID = service.Annotations[lbIDAnnotation]
			fipID = service.Annotations[floatingIPIDAnnotation]
		}

		if lbID != "" {
			if err := r.NHNClient.DeleteLoadBalancer(ctx, lbID); err != nil {
				if !strings.Contains(err.Error(), "404") {
					return ctrl.Result{}, err
				}
			}
		}

		if fipID != "" {
			if _, err := r.NHNClient.DisassociateFloatingIP(ctx, fipID); err != nil {
				if !strings.Contains(err.Error(), "404") {
					return ctrl.Result{}, err
				}
			}
		}

		patch := client.MergeFrom(service.DeepCopy())
		controllerutil.RemoveFinalizer(service, finalizerName)
		if err := r.Patch(ctx, service, patch); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) updateServiceStatus(ctx context.Context, service *corev1.Service, ipAddress string) (ctrl.Result, error) {

	// Get the latest service state to avoid conflicts
	var latestService corev1.Service
	if err := r.Get(ctx, client.ObjectKeyFromObject(service), &latestService); err != nil {
		return ctrl.Result{}, err
	}

	// Check if the current IP is already our floating IP
	if len(latestService.Status.LoadBalancer.Ingress) > 0 && latestService.Status.LoadBalancer.Ingress[0].IP == ipAddress {
		return ctrl.Result{}, nil
	}

	// Update the status with our floating IP
	patch := client.MergeFrom(latestService.DeepCopy())
	latestService.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ipAddress}}
	if err := r.Status().Patch(ctx, &latestService, patch); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue after a short delay to monitor and prevent other controllers from overwriting our IP
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *ServiceReconciler) updateServiceAnnotation(ctx context.Context, service *corev1.Service, key, value string) error {
	patch := client.MergeFrom(service.DeepCopy())
	if service.Annotations == nil {
		service.Annotations = make(map[string]string)
	}
	service.Annotations[key] = value
	return r.Patch(ctx, service, patch)
}

// getPortStatuses retrieves the current port reconciliation status from service annotations
func (r *ServiceReconciler) getPortStatuses(service *corev1.Service) (map[string]*PortStatus, error) {
	statuses := make(map[string]*PortStatus)

	if service.Annotations == nil {
		return statuses, nil
	}

	statusJson, exists := service.Annotations[portStatusAnnotation]
	if !exists {
		return statuses, nil
	}

	var portStatuses []*PortStatus
	if err := json.Unmarshal([]byte(statusJson), &portStatuses); err != nil {
		return statuses, err
	}

	for _, status := range portStatuses {
		key := fmt.Sprintf("%d-%s", status.Port, status.Protocol)
		statuses[key] = status
	}

	return statuses, nil
}

// updatePortStatus updates the status of a specific port and saves to service annotations
func (r *ServiceReconciler) updatePortStatus(ctx context.Context, service *corev1.Service, port corev1.ServicePort, status string, listenerID, poolID string) error {
	portStatuses, err := r.getPortStatuses(service)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%d-%s", port.Port, port.Protocol)
	portStatus, exists := portStatuses[key]
	if !exists {
		portStatus = &PortStatus{
			Port:     port.Port,
			Protocol: string(port.Protocol),
		}
		portStatuses[key] = portStatus
	}

	portStatus.Status = status
	if listenerID != "" {
		portStatus.ListenerID = listenerID
	}
	if poolID != "" {
		portStatus.PoolID = poolID
	}
	portStatus.LastReconciled = time.Now().Format(time.RFC3339)

	// Convert back to array
	var statusArray []*PortStatus
	for _, ps := range portStatuses {
		statusArray = append(statusArray, ps)
	}

	statusJson, err := json.Marshal(statusArray)
	if err != nil {
		return err
	}

	return r.updateServiceAnnotation(ctx, service, portStatusAnnotation, string(statusJson))
}

// isPortCompleted checks if a port has been fully reconciled
func (r *ServiceReconciler) isPortCompleted(service *corev1.Service, port corev1.ServicePort) bool {
	portStatuses, err := r.getPortStatuses(service)
	if err != nil {
		return false
	}

	key := fmt.Sprintf("%d-%s", port.Port, port.Protocol)
	status, exists := portStatuses[key]
	if !exists {
		return false
	}

	return status.Status == "active" && status.ListenerID != "" && status.PoolID != ""
}

func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Complete(r)
}
