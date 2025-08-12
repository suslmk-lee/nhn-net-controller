#!/bin/bash

set -eo pipefail

# --- 설정 변수 ---
NAMESPACE="k-paas-system"
DEPLOYMENT_NAME="controller-manager"
SERVICE_ACCOUNT_NAME="controller-manager"
K8S_SECRET_NAME="nhncloud-credentials"

OPENBAO_API_BASE="https://openbao.180.210.83.161.nip.io"
OPENBAO_KV_PATH="secret/data/cloud-controller/nhncloud"
OPENBAO_ROLE="controller-policy"

# 디버그 모드 설정
DEBUG_MODE="${DEBUG_MODE:-false}"

# OpenBao Root Token 경로 설정
OPENBAO_TOKEN_FILE="${OPENBAO_TOKEN_FILE:-~/workspace/container-platform/cp-portal-deployment/secmg/cp-vault-root-token}"
# ---

# --- 색상 및 로깅 함수 ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[0;36m'

log_info() {
    echo -e "${C_CYAN}[INFO]${C_RESET} $1"
}
log_success() {
    echo -e "${C_GREEN}[SUCCESS]${C_RESET} $1"
}
log_warn() {
    echo -e "${C_YELLOW}[WARNING]${C_RESET} $1"
}
log_debug() {
    if [ "$DEBUG_MODE" = "true" ]; then
        echo -e "${C_YELLOW}[DEBUG]${C_RESET} $1"
    fi
}
log_error() {
    echo -e "${C_RED}[ERROR]${C_RESET} $1" >&2
    exit 1
}

# Root token 읽기 함수
get_openbao_root_token() {
    # 환경 변수가 설정되어 있으면 우선 사용
    if [ -n "$OPENBAO_ROOT_TOKEN" ]; then
        echo "$OPENBAO_ROOT_TOKEN"
        return
    fi

    # 파일 경로 확장 (~/ -> 절대 경로)
    local token_file=$(eval echo "$OPENBAO_TOKEN_FILE")

    # 파일이 존재하고 읽을 수 있는지 확인
    if [ -f "$token_file" ] && [ -r "$token_file" ]; then
        local token=$(cat "$token_file" | tr -d '\n\r' | xargs)
        if [ -n "$token" ]; then
            log_debug "Root token을 파일에서 읽었습니다: $token_file" >&2
            echo "$token"
            return
        fi
    fi

    # 폴백: 기본 토큰 (개발/테스트용)
    log_warn "Root token 파일을 찾을 수 없습니다 ($token_file). 기본 토큰을 사용합니다." >&2
    echo "s.AYpIIy4k2ISqdCLO2nN4JZMe1a"
}

# Root token 설정
OPENBAO_ROOT_TOKEN=$(get_openbao_root_token)
# ---

# === 유틸리티 함수들 ===
check_prerequisites() {
    log_info "사전 환경을 체크합니다..."
    command -v kubectl >/dev/null 2>&1 || log_error "'kubectl' CLI를 찾을 수 없습니다."
    command -v curl >/dev/null 2>&1 || log_error "'curl'을 찾을 수 없습니다."
    command -v jq >/dev/null 2>&1 || log_error "'jq'를 찾을 수 없습니다. JSON 파싱을 위해 필요합니다."
}

ensure_service_account() {
    log_info "ServiceAccount '$SERVICE_ACCOUNT_NAME' 존재 여부를 확인하고, 없으면 생성합니다..."
    if ! kubectl get serviceaccount "$SERVICE_ACCOUNT_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        log_warn "ServiceAccount '$SERVICE_ACCOUNT_NAME'이(가) 없습니다. 새로 생성합니다."
        kubectl create serviceaccount "$SERVICE_ACCOUNT_NAME" -n "$NAMESPACE" || log_error "ServiceAccount 생성에 실패했습니다."
        log_success "ServiceAccount를 성공적으로 생성했습니다."
    else
        log_success "ServiceAccount가 이미 존재합니다."
    fi
}

validate_secret_exists() {
    kubectl get secret "$K8S_SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1 || \
        log_error "원본 Secret '$K8S_SECRET_NAME'을(를) '$NAMESPACE' 네임스페이스에서 찾을 수 없습니다."
}

# OpenBao API 호출 공통 함수
call_openbao_api() {
    local method="$1"
    local path="$2"
    local data="$3"
    local token="${4:-$OPENBAO_ROOT_TOKEN}"

    local curl_args=(
        -s
        -X "$method"
        -H "X-Vault-Token: $token"
        -H "Content-Type: application/json"
    )

    if [ -n "$data" ]; then
        curl_args+=(-d "$data")
    fi

    curl "${curl_args[@]}" "${OPENBAO_API_BASE}/v1${path}"
}

# HTTP 응답 파싱 함수
parse_http_response() {
    local response="$1"
    HTTP_CODE=$(echo "$response" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
    RESPONSE_BODY=$(echo "$response" | sed 's/HTTP_CODE:[0-9]*$//')
}

# === 1. 사전 환경 체크 ===
check_prerequisites
ensure_service_account
validate_secret_exists
log_success "사전 환경 체크 완료."

# OpenBao 설정 함수들
setup_kubernetes_auth() {
    log_info "Kubernetes 인증 방식을 설정합니다..."
    local k8s_api_server=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.server}')
    kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d > /tmp/k8s-ca.crt

    local k8s_ca_cert=$(cat /tmp/k8s-ca.crt | sed 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//')
    local config_data="{
        \"kubernetes_host\": \"${k8s_api_server}\",
        \"kubernetes_ca_cert\": \"${k8s_ca_cert}\"
    }"

    call_openbao_api "POST" "/auth/kubernetes/config" "$config_data" || \
        log_error "Kubernetes 인증 방식 설정에 실패했습니다."
}

create_policy() {
    log_info "controller-policy 정책을 생성합니다..."
    local policy_data='{
        "policy": "path \"secret/data/cloud-controller/nhncloud\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\npath \"secret/metadata/cloud-controller/nhncloud\" {\n  capabilities = [\"list\", \"read\", \"delete\"]\n}"
    }'

    call_openbao_api "PUT" "/sys/policies/acl/controller-policy" "$policy_data" || \
        log_error "controller-policy 정책 생성에 실패했습니다."
}

create_kubernetes_role() {
    log_info "Kubernetes 인증용 controller-policy role을 생성합니다..."
    local role_data="{
        \"bound_service_account_names\": [\"${SERVICE_ACCOUNT_NAME}\"],
        \"bound_service_account_namespaces\": [\"${NAMESPACE}\"],
        \"policies\": [\"controller-policy\"],
        \"ttl\": \"24h\"
    }"

    call_openbao_api "POST" "/auth/kubernetes/role/controller-policy" "$role_data" || \
        log_error "Kubernetes role 생성에 실패했습니다."
}

initialize_secret_path() {
    log_info "secret 경로를 초기화합니다..."
    local init_data='{"data": {}}'

    if ! call_openbao_api "PUT" "/secret/data/cloud-controller/nhncloud" "$init_data" >/dev/null 2>&1; then
        log_warn "경로 초기화에 실패했습니다. 기존 경로가 있을 수 있습니다."
    fi
}

# === 1.5. OpenBao 초기 설정 ===
setup_openbao() {
    log_info "OpenBao 초기 설정을 진행합니다..."

    setup_kubernetes_auth
    create_policy
    create_kubernetes_role
    initialize_secret_path

    log_success "OpenBao 초기 설정이 완료되었습니다."
}

setup_openbao

# Secret 읽기 함수
read_kubernetes_secret() {
    log_info "기존 Secret '$K8S_SECRET_NAME'에서 인증정보를 읽습니다..."

    # Kubernetes Secret 데이터를 OpenBao KV v2 형식으로 변환
    JSON_PAYLOAD_DATA=$(kubectl get secret "$K8S_SECRET_NAME" -n "$NAMESPACE" -o json | \
        jq '{data: (.data | to_entries | map({key: .key, value: (.value | @base64d)}) | from_entries)}')

    if [ -z "$JSON_PAYLOAD_DATA" ] || [ "$JSON_PAYLOAD_DATA" == "null" ]; then
        log_error "Secret '$K8S_SECRET_NAME'에서 데이터를 읽을 수 없습니다."
    fi

    log_debug "JSON Payload: $JSON_PAYLOAD_DATA"
    log_success "인증정보를 성공적으로 읽어 JSON 페이로드로 변환했습니다."
}

# === 2. Kubernetes Secret에서 인증정보 읽기 ===
read_kubernetes_secret

# OpenBao 인증 및 데이터 쓰기 함수들
authenticate_with_openbao() {
    log_info "서비스 어카운트 토큰을 가져옵니다 (kubectl create token 사용)..."
    K8S_SA_TOKEN=$(kubectl create token "$SERVICE_ACCOUNT_NAME" -n "$NAMESPACE" --duration=1h)
    if [ -z "$K8S_SA_TOKEN" ]; then
        log_error "서비스 어카운트 토큰을 가져오는 데 실패했습니다."
    fi
    log_debug "토큰 길이: ${#K8S_SA_TOKEN}"

    log_info "OpenBao에 로그인하여 클라이언트 토큰을 발급받습니다 (Role: $OPENBAO_ROLE)..."
    local login_payload="{\"role\":\"${OPENBAO_ROLE}\",\"jwt\":\"${K8S_SA_TOKEN}\"}"
    local login_response=$(curl --connect-timeout 5 -s -w "HTTP_CODE:%{http_code}" \
        --request POST --header "Content-Type: application/json" \
        --data "$login_payload" "${OPENBAO_API_BASE}/v1/auth/kubernetes/login")

    if [ $? -ne 0 ]; then
        log_error "OpenBao API(${OPENBAO_API_BASE})에 연결할 수 없습니다."
    fi

    parse_http_response "$login_response"
    log_debug "인증 HTTP Status: $HTTP_CODE"
    log_debug "인증 Response Body: $RESPONSE_BODY"

    OPENBAO_CLIENT_TOKEN=$(echo "$RESPONSE_BODY" | jq -r '.auth.client_token')
    if [ -z "$OPENBAO_CLIENT_TOKEN" ] || [ "$OPENBAO_CLIENT_TOKEN" == "null" ]; then
        log_error "OpenBao 클라이언트 토큰 획득에 실패했습니다. 역할(Role)과 인증 설정을 확인하세요."
    fi
    log_success "OpenBao 클라이언트 토큰을 성공적으로 발급받았습니다."
}

write_secret_to_openbao() {
    log_info "OpenBao 경로 '$OPENBAO_KV_PATH'에 데이터를 기록합니다..."
    log_debug "전체 URL = ${OPENBAO_API_BASE}/v1/${OPENBAO_KV_PATH}"

    local write_response=$(curl -s -w "HTTP_CODE:%{http_code}" \
        --request PUT \
        --header "X-Vault-Token: ${OPENBAO_CLIENT_TOKEN}" \
        --header "Content-Type: application/json" \
        --data "$JSON_PAYLOAD_DATA" \
        "${OPENBAO_API_BASE}/v1/${OPENBAO_KV_PATH}")

    parse_http_response "$write_response"
    log_debug "쓰기 HTTP Status: $HTTP_CODE"
    log_debug "쓰기 Response Body: $RESPONSE_BODY"

    if [ "$HTTP_CODE" -ne 200 ] && [ "$HTTP_CODE" -ne 204 ]; then
        log_error "OpenBao에 데이터 기록을 실패했습니다 (HTTP Status: $HTTP_CODE)."
    fi
}

verify_written_data() {
    log_info "데이터 기록 검증..."
    local verify_response_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --header "X-Vault-Token: ${OPENBAO_CLIENT_TOKEN}" \
        "${OPENBAO_API_BASE}/v1/${OPENBAO_KV_PATH}")

    if [ "$verify_response_code" -ne 200 ]; then
        log_error "기록된 데이터 검증에 실패했습니다 (HTTP Status: $verify_response_code)."
    fi
}

# === 3. OpenBao에 인증정보 쓰기 ===
migrate_secret_to_openbao() {
    log_info "OpenBao에 인증을 시도하고 Secret을 기록합니다..."

    authenticate_with_openbao
    write_secret_to_openbao
    verify_written_data

    log_success "OpenBao에 인증정보를 안전하게 기록하고 검증했습니다."
}

migrate_secret_to_openbao

# Deployment 설정 변경 함수들
update_deployment_config() {
    log_info "Deployment '$DEPLOYMENT_NAME'의 설정을 변경합니다..."

    # 기존 ConfigMap 참조 찾기
    local config_map_name=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].envFrom[?(@.configMapRef)].configMapRef.name}' 2>/dev/null)

    if [ -z "$config_map_name" ]; then
        log_warn "기존 ConfigMap 참조를 찾지 못했습니다. 빈 envFrom을 사용합니다."
        config_map_name=""
    fi

    # JSON patch 생성
    local patch_payload
    if [ -n "$config_map_name" ]; then
        patch_payload=$(cat <<EOF
[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/envFrom",
    "value": [
      { "configMapRef": { "name": "${config_map_name}" } }
    ]
  },
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/env",
    "value": [
      { "name": "SECRET_MANAGEMENT_MODE", "value": "openbao" },
      { "name": "OPENBAO_ADDR", "value": "${OPENBAO_API_BASE}" },
      { "name": "OPENBAO_PATH", "value": "${OPENBAO_KV_PATH}" },
      { "name": "OPENBAO_ROLE", "value": "${OPENBAO_ROLE}" },
      { "name": "CONTROLLER_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } }
    ]
  }
]
EOF
)
    else
        patch_payload=$(cat <<EOF
[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/env",
    "value": [
      { "name": "SECRET_MANAGEMENT_MODE", "value": "openbao" },
      { "name": "OPENBAO_ADDR", "value": "${OPENBAO_API_BASE}" },
      { "name": "OPENBAO_PATH", "value": "${OPENBAO_KV_PATH}" },
      { "name": "OPENBAO_ROLE", "value": "${OPENBAO_ROLE}" },
      { "name": "CONTROLLER_NAMESPACE", "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } } }
    ]
  }
]
EOF
)
    fi

    kubectl patch deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --type='json' -p="$patch_payload" || \
        log_error "Deployment patch 적용에 실패했습니다."

    log_success "Deployment에 OpenBao 설정을 적용했습니다."
}

wait_for_deployment_rollout() {
    log_info "컨트롤러의 재시작 상태를 확인합니다 (최대 2분 대기)..."
    if ! kubectl rollout status deployment/"$DEPLOYMENT_NAME" -n "$NAMESPACE" --timeout=120s; then
        log_error "컨트롤러가 시간 내에 정상적으로 재시작되지 못했습니다. 'kubectl get pods -n $NAMESPACE'로 상태를 확인하세요."
    fi
    log_success "컨트롤러가 성공적으로 재시작되었습니다."
}

cleanup_original_secret() {
    echo ""
    read -p "마이그레이션이 성공적으로 완료되었습니다. 원본 Kubernetes Secret '$K8S_SECRET_NAME'을(를) 삭제하시겠습니까? (y/N): " choice
    case "$choice" in
      y|Y )
        log_info "원본 Secret '$K8S_SECRET_NAME'을(를) 삭제합니다..."
        kubectl delete secret "$K8S_SECRET_NAME" -n "$NAMESPACE"
        log_success "원본 Secret을 삭제했습니다."
        ;;
      * )
        log_info "원본 Secret 삭제를 건너뜁니다."
        ;;
    esac
}

# === 4-6. Deployment 설정 변경 및 마무리 ===
finalize_migration() {
    # Deployment가 존재하는지 확인
    if kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        update_deployment_config
        wait_for_deployment_rollout
    else
        log_warn "Deployment '$DEPLOYMENT_NAME'을 찾을 수 없습니다. Deployment 설정 변경을 건너뜁니다."
    fi

    cleanup_original_secret

    echo -e "\\n${C_GREEN}🎉 모든 마이그레이션 과정이 완료되었습니다!${C_RESET}"
}

finalize_migration