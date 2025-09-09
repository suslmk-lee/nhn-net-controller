# UPDATE.md

## Version 1.0.2 Release Notes (2025-09-09)

### 🚀 Major Bug Fixes

#### 1. Service Type Change Handling Fix
**Issue**: When changing a LoadBalancer service to ClusterIP and back to LoadBalancer, the controller failed to create a new LoadBalancer due to stale port status annotations.

**Root Cause**: The `handleServiceDeletion` function was not properly cleaning up NHN Cloud annotations, particularly `nhn.cloud/port-status`, causing the controller to skip port processing with "Port already completed, skipping" messages.

**Solution**: Enhanced `handleServiceDeletion` function to automatically remove all NHN Cloud annotations during cleanup:

```go
// Clean up all NHN Cloud annotations
if service.Annotations != nil {
    delete(service.Annotations, lbIDAnnotation)
    delete(service.Annotations, floatingIPIDAnnotation)
    delete(service.Annotations, controllerAnnotation)
    delete(service.Annotations, portStatusAnnotation)
}
```

**Impact**: 
- ✅ Service type changes now work seamlessly
- ✅ No manual annotation cleanup required
- ✅ Prevents "Port already completed" false positives

#### 2. OpenBao AppRole Authentication Enhancement
**Issue**: Missing `secret_id` in OpenBao AppRole authentication requests causing "missing secret_id" errors.

**Root Cause**: The `AppRoleAuthRequest` structure was not including the `secret_id` field in authentication requests.

**Solution**: 
- Updated `getAppRoleCredentials()` function signature to return `secretID`
- Enhanced `authenticateWithOpenBao()` to include `secret_id` in requests
- Added proper validation for `VAULT_SECRET_ID` presence

**Impact**:
- ✅ Full OpenBao AppRole authentication support
- ✅ Supports both role_id and secret_id authentication
- ✅ Better error handling for missing credentials

### 🔧 Technical Improvements

#### Multi-Backend Secret Management
The controller now supports sophisticated secret detection with the following priority:
1. **OpenBao** (Highest security) - Enterprise-grade secret management
2. **External Secrets Operator** (Cloud integration) - AWS/Azure/GCP secret services
3. **Kubernetes Secrets** (Fallback) - Traditional secret management

#### Registry Migration
- Updated from `registry-dev2.k-paas.org` to `registry.k-paas.org`
- Improved image distribution and availability

### 🧪 Testing Results

#### Service Type Change Test Scenario
**Test Flow**:
1. Create LoadBalancer service → External IP: `133.186.218.173` ✅
2. Change to ClusterIP → All NHN Cloud annotations removed ✅  
3. Change back to LoadBalancer → New External IP: `133.186.247.95` ✅

**Before Fix**:
```
2025-09-09T07:26:49Z DEBUG Port already completed, skipping
2025-09-09T07:26:50Z DEBUG Port already completed, skipping
```

**After Fix**:
```
2025-09-09T08:21:40Z INFO Processing port
2025-09-09T08:21:42Z INFO Port needs requeue, continuing with other ports
```

### 🔄 Migration Guide

#### For Existing Deployments
1. Update deployment image to `registry.k-paas.org/kpaas/nhn-controller:v1.0.2`
2. No configuration changes required
3. Existing services continue to work without interruption

#### For New Deployments
```yaml
image: registry.k-paas.org/kpaas/nhn-controller:v1.0.2
```

### 🛠 Developer Notes

#### Code Changes
- **File**: `internal/controller/service_controller.go`
  - Enhanced `handleServiceDeletion()` function with annotation cleanup
  
- **File**: `internal/config/detector.go` 
  - Updated OpenBao AppRole authentication flow
  - Added `secret_id` support in authentication requests

#### Deployment Files Updated
- **File**: `k8s/deploy.yaml`
  - Updated image registry domain
  - Updated image tag to `v1.0.2`

### 🐛 Known Issues Resolved

1. ✅ **Service Type Change Loop**: Fixed infinite pending state when changing service types
2. ✅ **OpenBao Authentication**: Resolved missing secret_id errors  
3. ✅ **Registry Access**: Fixed image pull failures with new registry domain
4. ✅ **Annotation Cleanup**: Automated removal of stale NHN Cloud annotations

### 📋 Verification Commands

```bash
# Check controller version
kubectl get deployment controller-manager -n k-paas-system -o jsonpath='{.spec.template.spec.containers[0].image}'

# Test service type change
kubectl patch svc <service-name> -p '{"spec":{"type":"ClusterIP"}}'
kubectl patch svc <service-name> -p '{"spec":{"type":"LoadBalancer"}}'

# Verify annotation cleanup
kubectl get svc <service-name> -o yaml | grep "nhn.cloud"
```

---

## Previous Versions

### Version 1.0.1
- Initial OpenBao integration
- Multi-port service support enhancement
- ConfigMap-based configuration management

### Version 1.0.0
- Initial release with basic NHN Cloud LoadBalancer support
- Core reconciliation logic
- Finalizer-based resource cleanup