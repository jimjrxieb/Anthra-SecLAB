# Portfolio MVP - Local Kubernetes Deployment & DevSecOps
.PHONY: help build-kind build-minikube deploy-kind deploy-minikube logs clean security-scan helm-security

help:
	@echo "Portfolio MVP - Local Kubernetes Commands"
	@echo ""
	@echo "KIND (recommended):"
	@echo "  make build-kind      - Create kind cluster + build/load images"
	@echo "  make deploy-kind     - Deploy Portfolio to kind cluster"
	@echo "  make logs-kind       - Show logs from kind deployment"
	@echo "  make clean-kind      - Delete kind cluster"
	@echo ""
	@echo "MINIKUBE:"
	@echo "  make build-minikube  - Start minikube + build images"
	@echo "  make deploy-minikube - Deploy Portfolio to minikube"
	@echo "  make logs-minikube   - Show logs from minikube deployment"
	@echo "  make clean-minikube  - Stop minikube"
	@echo ""
	@echo "General:"
	@echo "  make test           - Test the deployment"
	@echo "  make port-forward   - Port forward services (if no ingress)"
	@echo ""
	@echo "DevSecOps:"
	@echo "  make security-scan  - Run security scans (Trivy, SBOM)"
	@echo "  make helm-security  - Validate Helm security (kubeconform, Conftest)"
	@echo "  make scan-images    - Scan container images for vulnerabilities"
	@echo "  make render-helm    - Render Helm templates for validation"
	@echo "  make security-report - Generate compliance report"
	@echo "  make security-demo   - Run complete security demonstration"

# KIND targets
build-kind:
	@echo "🔨 Creating kind cluster with nginx ingress..."
	kind create cluster --name portfolio
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
	kubectl wait --namespace ingress-nginx --for=condition=Ready pods --selector=app.kubernetes.io/component=controller --timeout=120s
	@echo "🐳 Building and loading Docker images..."
	docker build -t ghcr.io/shadow-link-industries/portfolio-api:local ./api
	docker build -t ghcr.io/shadow-link-industries/portfolio-ui:local ./ui
	kind load docker-image ghcr.io/shadow-link-industries/portfolio-api:local --name portfolio
	kind load docker-image ghcr.io/shadow-link-industries/portfolio-ui:local --name portfolio
	@echo "✅ Kind cluster ready!"

deploy-kind: build-kind
	@echo "🚀 Deploying Portfolio to kind..."
	kubectl apply -k k8s/overlays/local
	@echo "⏳ Waiting for pods to be ready..."
	kubectl -n portfolio wait --for=condition=Ready pods --all --timeout=300s
	@echo "✅ Deployment complete!"
	@echo "🌐 Open http://portfolio.localtest.me"
	@echo "🔍 Health: curl -s http://portfolio.localtest.me/api/health"

# MINIKUBE targets
build-minikube:
	@echo "🔨 Starting minikube with ingress..."
	minikube start
	minikube addons enable ingress
	@echo "🐳 Building Docker images in minikube..."
	eval $$(minikube docker-env) && \
	docker build -t ghcr.io/shadow-link-industries/portfolio-api:local ./api && \
	docker build -t ghcr.io/shadow-link-industries/portfolio-ui:local ./ui
	@echo "✅ Minikube ready!"

deploy-minikube: build-minikube
	@echo "🚀 Deploying Portfolio to minikube..."
	kubectl apply -k k8s/overlays/local
	@echo "⏳ Waiting for pods to be ready..."
	kubectl -n portfolio wait --for=condition=Ready pods --all --timeout=300s
	@echo "✅ Deployment complete!"
	@echo "🌐 Add to /etc/hosts: echo \"$$(minikube ip) portfolio.localtest.me\" | sudo tee -a /etc/hosts"
	@echo "🌐 Then open http://portfolio.localtest.me"

# Logging and monitoring
logs-kind logs-minikube:
	@echo "📊 Portfolio API logs:"
	kubectl -n portfolio logs -l app=portfolio-api --tail=50
	@echo ""
	@echo "📊 Portfolio UI logs:"
	kubectl -n portfolio logs -l app=portfolio-ui --tail=20

# Testing
test:
	@echo "🧪 Testing Portfolio deployment..."
	@echo "Checking API health..."
	kubectl -n portfolio get pods
	kubectl -n portfolio exec deploy/portfolio-api -- curl -f http://localhost:8000/health || echo "❌ API health check failed"
	@echo "Checking UI..."
	kubectl -n portfolio exec deploy/portfolio-ui -- curl -f http://localhost:5173/ || echo "❌ UI health check failed"

# Port forwarding (if ingress doesn't work)
port-forward:
	@echo "🔗 Port forwarding services..."
	@echo "UI: http://localhost:5173"
	@echo "API: http://localhost:8000"
	kubectl -n portfolio port-forward svc/portfolio-ui 5173:80 &
	kubectl -n portfolio port-forward svc/portfolio-api 8000:80 &
	@echo "Press Ctrl+C to stop port forwarding"

# Cleanup
clean-kind:
	@echo "🧹 Deleting kind cluster..."
	kind delete cluster --name portfolio

clean-minikube:
	@echo "🧹 Stopping minikube..."
	minikube stop
	minikube delete

# Status
status:
	@echo "📊 Portfolio Status:"
	kubectl -n portfolio get pods,svc,ing
	@echo ""
	kubectl -n portfolio describe ing portfolio-ingress

# ==============================================================================
# DevSecOps Security Targets
# ==============================================================================

# Security scanning
security-scan: scan-images generate-sbom

# Scan container images with Trivy
scan-images:
	@echo "🔍 Scanning container images for vulnerabilities..."
	@echo "Building images first..."
	docker build -t ghcr.io/shadow-link-industries/portfolio-api:dev ./api
	docker build -t ghcr.io/shadow-link-industries/portfolio-ui:dev ./ui
	@echo "Running Trivy scans..."
	trivy image --severity HIGH,CRITICAL ghcr.io/shadow-link-industries/portfolio-api:dev
	trivy image --severity HIGH,CRITICAL ghcr.io/shadow-link-industries/portfolio-ui:dev

# Generate SBOM for images
generate-sbom:
	@echo "📄 Generating Software Bill of Materials (SBOM)..."
	mkdir -p evidence
	syft packages ghcr.io/shadow-link-industries/portfolio-api:dev -o spdx-json > evidence/sbom-api-$(shell date +%s).json
	syft packages ghcr.io/shadow-link-industries/portfolio-ui:dev -o spdx-json > evidence/sbom-ui-$(shell date +%s).json
	@echo "✅ SBOM reports saved to evidence/ directory"

# Helm security validation
helm-security: render-helm kubeconform conftest

# Render Helm templates
render-helm:
	@echo "📝 Rendering Helm templates..."
	helm template portfolio ./charts/portfolio \
		--set image.repository=ghcr.io/shadow-link-industries/portfolio-api \
		--set image.tag=dev \
		--set ui.image.repository=ghcr.io/shadow-link-industries/portfolio-ui \
		--set ui.image.tag=dev \
		--set networkPolicy.enabled=true \
		--set podSecurityStandards.enabled=true \
		--set gatekeeper.enabled=true > rendered-manifests.yaml
	@echo "✅ Manifests rendered to rendered-manifests.yaml"

# Validate Kubernetes manifests with kubeconform
kubeconform: render-helm
	@echo "✅ Validating Kubernetes manifests with kubeconform..."
	@if command -v kubeconform >/dev/null 2>&1; then \
		kubeconform -strict -summary -kubernetes-version 1.29.0 -schema-location default rendered-manifests.yaml; \
	else \
		echo "❌ kubeconform not installed. Installing..."; \
		curl -L https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz | tar -xz; \
		sudo mv kubeconform /usr/local/bin/; \
		kubeconform -strict -summary -kubernetes-version 1.29.0 -schema-location default rendered-manifests.yaml; \
	fi

# Run Conftest policies against rendered manifests
conftest: render-helm
	@echo "🔒 Running security policies with Conftest..."
	@if command -v conftest >/dev/null 2>&1; then \
		conftest test rendered-manifests.yaml --policy charts/portfolio/policies/; \
	else \
		echo "❌ conftest not installed. Installing..."; \
		wget https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz; \
		tar xzf conftest_0.46.0_Linux_x86_64.tar.gz; \
		sudo mv conftest /usr/local/bin; \
		rm conftest_0.46.0_Linux_x86_64.tar.gz; \
		conftest test rendered-manifests.yaml --policy charts/portfolio/policies/; \
	fi

# Sign images with Cosign (requires cosign to be installed)
sign-images:
	@echo "✍️ Signing container images with Cosign..."
	@if command -v cosign >/dev/null 2>&1; then \
		echo "Signing API image..."; \
		cosign sign --yes ghcr.io/shadow-link-industries/portfolio-api:dev; \
		echo "Signing UI image..."; \
		cosign sign --yes ghcr.io/shadow-link-industries/portfolio-ui:dev; \
	else \
		echo "❌ cosign not installed. Install with: go install github.com/sigstore/cosign/v2/cmd/cosign@latest"; \
	fi

# Verify signed images
verify-images:
	@echo "🔐 Verifying signed container images..."
	@if command -v cosign >/dev/null 2>&1; then \
		cosign verify ghcr.io/shadow-link-industries/portfolio-api:dev; \
		cosign verify ghcr.io/shadow-link-industries/portfolio-ui:dev; \
	else \
		echo "❌ cosign not installed"; \
	fi

# Full security validation pipeline
security-full: security-scan helm-security
	@echo "🛡️ Full security validation complete!"
	@echo "📊 Summary:"
	@echo "  ✅ Container images scanned with Trivy"
	@echo "  ✅ SBOM generated"
	@echo "  ✅ Helm templates validated with kubeconform"
	@echo "  ✅ Security policies enforced with Conftest"

# Clean security artifacts
security-clean:
	@echo "🧹 Cleaning security artifacts..."
	rm -f rendered-manifests.yaml
	rm -f conftest_*.tar.gz
	rm -rf evidence/
	@echo "✅ Security artifacts cleaned"

# Install security tools
install-security-tools:
	@echo "📦 Installing security tools..."
	@echo "Installing trivy..."
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
	@echo "Installing syft..."
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
	@echo "Installing kubeconform..."
	curl -L https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz | tar -xz
	sudo mv kubeconform /usr/local/bin/
	@echo "Installing conftest..."
	wget https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz
	tar xzf conftest_0.46.0_Linux_x86_64.tar.gz
	sudo mv conftest /usr/local/bin
	rm conftest_0.46.0_Linux_x86_64.tar.gz
	@echo "✅ Security tools installed"

# Generate security compliance report
security-report:
	@echo "📊 Generating security compliance report..."
	./scripts/generate-security-report.sh

# Complete security demonstration
security-demo: security-full security-report
	@echo "🎯 Complete security demonstration finished!"
	@echo "📋 Summary:"
	@echo "  1. ✅ Container images scanned"
	@echo "  2. ✅ SBOM generated"
	@echo "  3. ✅ Helm manifests validated"
	@echo "  4. ✅ Security policies tested"
	@echo "  5. ✅ Compliance report generated"
	@echo ""
	@echo "🔒 Your Portfolio is now a DevSecOps showcase!"
