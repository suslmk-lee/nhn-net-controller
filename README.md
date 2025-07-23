# NHN Cloud 로드밸런서 컨트롤러

쿠버네티스 `Service` 리소스 타입 중 `LoadBalancer`를 위해 NHN Cloud 로드밸런서를 자동으로 생성하고 관리하는 쿠버네티스 컨트롤러입니다.

## 기능 설명

이 컨트롤러는 쿠버네티스 클러스터 내에서 `LoadBalancer` 타입의 서비스가 생성되는 것을 감시하고, 이에 맞춰 NHN Cloud 로드밸런서를 자동으로 생성합니다. 서비스가 삭제되면, 해당 로드밸런서도 자동으로 삭제되어 리소스를 효율적으로 관리할 수 있습니다. 이를 통해 쿠버네티스와 NHN Cloud 로드밸런서 서비스를 매끄럽게 통합하여 사용할 수 있습니다.

---

## 운영 환경 배포 가이드

이 가이드는 사전에 빌드되어 컨테이너 레지스트리에 업로드된 컨트롤러 이미지를 사용하여, 소스 코드 없이 실제 쿠버네티스 운영 환경에 배포하는 방법을 설명합니다.

### 1단계: 사전 준비

배포를 진행할 터미널 환경에 아래 도구와 정보가 준비되어 있어야 합니다.

1.  **`kubectl` 설치 및 설정:** 배포할 쿠버네티스 클러스터에 접근할 수 있도록 `kubectl`이 설치되고 설정되어 있어야 합니다.
2.  **NHN Cloud 인증 정보:** 아래의 NHN Cloud 계정 정보가 필요합니다.
    *   NHN Cloud 계정 아이디 (이메일)
    *   NHN Cloud 계정 비밀번호
    *   사용할 프로젝트의 테넌트(Tenant) ID
    *   로드밸런서 VIP(가상 IP)를 할당할 서브넷(Subnet) ID

### 2단계: 인증 정보 시크릿 생성

컨트롤러가 사용할 전용 네임스페이스와 NHN Cloud 인증 정보를 담을 쿠버네티스 시크릿을 생성합니다.

1.  **네임스페이스 생성:**
    컨트롤러와 관련 리소스가 설치될 `k-paas-system` 네임스페이스를 생성합니다.

    ```sh
    kubectl create namespace k-paas-system
    ```

2.  **인증 정보 시크릿 생성:**
    NHN Cloud 인증에 필요한 모든 정보를 담은 쿠버네티스 시크릿을 생성합니다. 아래 명령어에서 `your-`로 시작하는 값들을 **본인의 실제 정보로 교체**하여 실행하세요.

    ```sh
    kubectl create secret generic nhncloud-credentials \
      -n k-paas-system \
      --from-literal=NHN_API_BASE_URL="https://kr1-api-network-infrastructure.nhncloudservice.com" \
      --from-literal=NHN_AUTH_URL="https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens" \
      --from-literal=NHN_TENANT_ID="your-tenant-id" \
      --from-literal=NHN_USERNAME="your-nhn-cloud-email" \
      --from-literal=NHN_PASSWORD="your-nhn-cloud-password" \
      --from-literal=NHN_VIP_SUBNET_ID="your-vip-subnet-id"
    ```

     🎱 Tenant ID는 NHN Cloud Console에서 확인할 수 있습니다. (API 엔드포인트 클릭)

    <img width="1092" height="369" alt="Image" src="https://github.com/user-attachments/assets/ad4dc0bf-c95a-4ce8-8c75-e1dc7cedcc28" />

### 3단계: 컨트롤러 배포

1.  **배포 실행:**
    프로젝트에 포함된 `k8s/deploy.yaml` 파일을 사용하여 클러스터에 컨트롤러를 배포합니다. 이 파일은 운영에 필요한 모든 리소스를 포함하고 있습니다.

    ```sh
    # 만약 소스 코드를 clone하지 않았다면, 아래 YAML 내용을 deploy.yaml로 저장하여 사용하세요.
    kubectl apply -f k8s/deploy.yaml
    ```

2.  **배포 상태 확인:**
    컨트롤러 파드가 정상적으로 실행되는지 확인합니다. `STATUS`가 `Running`으로 표시될 때까지 잠시 기다립니다.

    ```sh
    kubectl get pods -n k-paas-system
    ```

### 4단계: 기능 테스트

컨트롤러가 정상적으로 배포되었다면, `LoadBalancer` 타입의 서비스를 생성하여 기능이 올바르게 동작하는지 최종 테스트합니다.

1.  **테스트용 서비스 생성:**
    아래 내용을 `test-service.yaml` 파일로 저장한 후 적용합니다.

    ```yaml
    # test-service.yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: my-nginx-service
    spec:
      type: LoadBalancer
      selector:
        app: nginx
      ports:
        - protocol: TCP
          port: 80
          targetPort: 80
    --- 
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
          - name: nginx
            image: nginx:latest
            ports:
            - containerPort: 80
    ```

    ```sh
    kubectl apply -f test-service.yaml
    ```

2.  **동작 확인:**
    잠시 후 아래 명령을 실행하여 `my-nginx-service`의 `EXTERNAL-IP` 항목에 NHN Cloud 로드밸런서의 VIP가 할당되었는지 확인합니다.

    ```sh
    kubectl get service my-nginx-service
    ```

---

## 리소스 정리

배포된 컨트롤러와 관련 리소스를 삭제하려면 아래 명령어를 사용합니다.

```sh
# 테스트 서비스 및 디플로이먼트 삭제
kubectl delete -f test-service.yaml

# 컨트롤러 및 관련 리소스 삭제
kubectl delete -f k8s/deploy.yaml

# 시크릿 삭제
kubectl delete secret nhncloud-credentials -n k-paas-system
```

---

## 개발자를 위한 정보

### 소스 코드로 빌드 및 배포

이 프로젝트의 소스 코드를 직접 수정하고 빌드하여 테스트하려면 아래의 `make` 명령어들을 사용할 수 있습니다.

- **`make run`**: 로컬 머신에서 컨트롤러를 실행합니다. `.env` 파일에 NHN Cloud 인증 정보를 설정해야 합니다.
- **`make docker-build`**: 컨트롤러의 Docker 이미지를 빌드합니다.
- **`make docker-push`**: 빌드된 이미지를 레지스트리로 푸시합니다.
- **`make deploy`**: 소스 코드의 `config` 디렉토리 기준으로 컨트롤러를 클러스터에 배포합니다.

*자세한 내용은 `Makefile`을 참고하세요.*

## 라이선스

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
