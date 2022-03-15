# General release info
BUILD_DATE        := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
BUILD_VERSION     := 0.1.0
DOCKER_ACCOUNT    := boeboe
CONTAINER_NAME    := istio-cert-secret-creator-test
IMAGE_DESCRIPTION := Istio certificate secret creator container image
IMAGE_NAME        := istio-cert-secret-creator
APP_VERSION       := 0.1.0
REPO_URL          := https://github.com/boeboe/istio-cert-secret-creator
URL               := https://github.com/boeboe/istio-cert-secret-creator

BUILD_ARGS := --build-arg BUILD_DATE="${BUILD_DATE}" \
							--build-arg BUILD_VERSION="${BUILD_VERSION}" \
							--build-arg DOCKER_ACCOUNT="${DOCKER_ACCOUNT}" \
							--build-arg IMAGE_DESCRIPTION="${IMAGE_DESCRIPTION}" \
							--build-arg IMAGE_NAME="${IMAGE_NAME}" \
							--build-arg APP_VERSION="${APP_VERSION}" \
							--build-arg REPO_URL="${REPO_URL}" \
							--build-arg URL="${URL}" \
							--build-arg REPO_URL="${REPO_URL}"

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

build: ## Build the container
	docker build ${BUILD_ARGS} --no-cache -t $(DOCKER_ACCOUNT)/${IMAGE_NAME} .

run: ## Run container
	docker run -it --rm --mount type=bind,source=${HOME}/.kube,target=/root/.kube \
		--name=$(CONTAINER_NAME) $(DOCKER_ACCOUNT)/$(IMAGE_NAME)

shell: ## Run shell in container
	docker run -it --rm --mount type=bind,source=${HOME}/.kube,target=/root/.kube \
		--name=$(CONTAINER_NAME) --entrypoint=/bin/bash $(DOCKER_ACCOUNT)/$(IMAGE_NAME)

stop: ## Stop and remove a running container
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true

publish: ## Tag and publish container
	docker tag $(DOCKER_ACCOUNT)/${IMAGE_NAME} $(DOCKER_ACCOUNT)/${IMAGE_NAME}:${BUILD_VERSION}
	docker push $(DOCKER_ACCOUNT)/${IMAGE_NAME}:${BUILD_VERSION}

release: build publish ## Make a full release
	@echo "Check released tags on https://hub.docker.com/r/$(DOCKER_ACCOUNT)/${IMAGE_NAME}/tags"

deploy: ## Deploy within the istio-system namespace
	kubectl apply -n istio-system -f kubernetes/cert-creator.yaml

undeploy: ## Undeploy from the istio-system namespace
	kubectl delete -n istio-system -f kubernetes/cert-creator.yaml

deploy-test: ## Create some test namespaces and serviceaccounts
	kubectl apply -f kubernetes/test-pem.yaml
	kubectl apply -f kubernetes/test-pkcs12.yaml

undeploy-test: ## Delete the test namespaces and serviceaccounts
	kubectl delete -f kubernetes/test-pem.yaml
	kubectl delete -f kubernetes/test-pkcs12.yaml
