.PHONY: build clean help push tag

# Variables
IMAGE_NAME := cinc-auditor-oracle
CONTAINER_NAME := cinc-auditor-oracle
#PLATFORM := linux/amd64
PLATFORM := linux/arm64
DOCKER_USERNAME ?= peterburkholdergsa
VERSION ?= latest

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the Docker image with platform specification
	docker build --platform $(PLATFORM) -t $(IMAGE_NAME) .

clean: ## Remove the Docker image
	docker rmi $(IMAGE_NAME) || true
	docker rmi $(DOCKER_USERNAME)/$(IMAGE_NAME):$(VERSION) || true

rebuild: clean build ## Clean and rebuild the image

tag: ## Tag image for Docker Hub (set DOCKER_USERNAME and VERSION)
	docker tag $(IMAGE_NAME) $(DOCKER_USERNAME)/$(IMAGE_NAME):$(VERSION)
	@echo "Tagged as $(DOCKER_USERNAME)/$(IMAGE_NAME):$(VERSION)"

push: tag ## Push image to Docker Hub (requires docker login)
	docker push $(DOCKER_USERNAME)/$(IMAGE_NAME):$(VERSION)
	@echo "Pushed $(DOCKER_USERNAME)/$(IMAGE_NAME):$(VERSION)"
