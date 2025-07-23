package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/suslmk-lee/kube-controller02/pkg/nhncloud"
)

var _ = Describe("Service Controller", func() {

	const (
		serviceName = "test-service"
		namespace   = "default"
		floatingIP  = "1.2.3.4"
		nodeName    = "test-node"
		nodeIP      = "10.0.0.1"
	)

	var (
		ctx            context.Context
		mockServer     *httptest.Server
		nhnClient      *nhncloud.Client
		service        *corev1.Service
		node           *corev1.Node
		namespacedName types.NamespacedName
		k8sReconciler  *ServiceReconciler
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespacedName = types.NamespacedName{Name: serviceName, Namespace: namespace}

		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			// Auth
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/tokens":
				w.WriteHeader(http.StatusOK)
				expires := time.Now().Add(1 * time.Hour).Format(time.RFC3339Nano)
				fmt.Fprintf(w, `{"access":{"token":{"id":"mock-token","expires":"%s"}}}`, expires)
			// LB Create
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/lbaas/loadbalancers":
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprintf(w, `{"loadbalancer": {"id": "%s", "provisioning_status": "PENDING_CREATE"}}`, uuid.New().String())
			// LB Get
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2.0/lbaas/loadbalancers/"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"loadbalancer": {"id": "%s", "provisioning_status": "ACTIVE", "vip_port_id": "port-123"}}`, uuid.New().String())
			// Listener Create
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/lbaas/listeners":
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"listener": {"id": "%s"}}`, uuid.New().String())
			// Pool Create
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/lbaas/pools":
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"pool": {"id": "%s"}}`, uuid.New().String())
			// HealthMonitor List (return empty to trigger creation)
			case r.Method == http.MethodGet && r.URL.Path == "/v2.0/lbaas/healthmonitors":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"healthmonitors": []}`)
			// HealthMonitor Create
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/lbaas/healthmonitors":
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"healthmonitor": {"id": "%s"}}`, uuid.New().String())
			// Member List (return empty to trigger creation)
			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/members"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"members": []}`)
			// Member Create
			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/members"):
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"member": {"id": "%s"}}`, uuid.New().String())
			// Get External Network ID
			case r.Method == http.MethodGet && r.URL.Path == "/v2.0/vpcs" && r.URL.RawQuery == "router:external=true":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"vpcs": [{"id": "ext-net-id", "router:external": true}]}`)
			// Floating IP Create
			case r.Method == http.MethodPost && r.URL.Path == "/v2.0/floatingips":
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintf(w, `{"floatingip": {"id": "%s", "floating_ip_address": "%s"}}`, uuid.New().String(), floatingIP)
			// Floating IP Get
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2.0/floatingips/"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"floatingip": {"id": "%s", "floating_ip_address": "%s", "port_id": "port-123"}}`, uuid.New().String(), floatingIP)
			// Floating IP Associate
			case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v2.0/floatingips/"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"floatingip": {"id": "%s", "port_id": "port-123"}}`, uuid.New().String())
			default:
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"error": "Not Found"}`)
			}
		}))

		nhnClient = nhncloud.NewClient(mockServer.URL, mockServer.URL+"/v2.0/tokens", "test-tenant", "test-user", "test-password")
		k8sReconciler = &ServiceReconciler{
			Client:    k8sClient,
			Scheme:    k8sClient.Scheme(),
			NHNClient: nhnClient,
		}

		// Create a test node
		node = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName},
			Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: nodeIP}}},
		}
		Expect(k8sClient.Create(ctx, node)).Should(Succeed())

		// Create a test service
		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceName,
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{{
					Port:     80,
					NodePort: 30080,
				}},
			},
		}
		Expect(k8sClient.Create(ctx, service)).Should(Succeed())
	})

	AfterEach(func() {
		mockServer.Close()
		Expect(k8sClient.Delete(ctx, service)).Should(Succeed())
		Expect(k8sClient.Delete(ctx, node)).Should(Succeed())
	})

	It("should set the floating IP on the service status", func() {
		// We might need to reconcile multiple times for all resources to be created and status to be updated.
		// The Eventually block will handle the retries.
		Eventually(func() (string, error) {
			_, err := k8sReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName})
			if err != nil {
				// Don't return the error to allow Eventually to retry
				return "", nil
			}

			var updatedService corev1.Service
			if err := k8sClient.Get(ctx, namespacedName, &updatedService); err != nil {
				return "", err
			}

			if len(updatedService.Status.LoadBalancer.Ingress) > 0 {
				return updatedService.Status.LoadBalancer.Ingress[0].IP, nil
			}
			return "", nil
		}, time.Second*20, time.Millisecond*250).Should(Equal(floatingIP))
	})
})
