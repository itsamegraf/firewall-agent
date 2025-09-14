# firewall-agent project Makefile

# Basic knobs
STACK       ?= firewall-agent
REGISTRY    ?= ghcr.io
OWNER       ?= itsamegraf
TAG         ?= latest
PLATFORMS   ?= linux/amd64

# Derived
IMG_AGENT   := $(REGISTRY)/$(OWNER)/firewall-agent:$(TAG)
IMG_UI      := $(REGISTRY)/$(OWNER)/firewall-agent-ui:$(TAG)
SERV_AGENT  := $(STACK)_firewall-agent
SERV_UI     := $(STACK)_firewall-agent-ui

.PHONY: help
help:
	@echo "Common targets:"
	@echo "  build-local           Build agent+ui images locally (tags :local)"
	@echo "  build-agent-local     Build firewall-agent:local"
	@echo "  build-ui-local        Build firewall-agent-ui:local"
	@echo "  deploy-local          Deploy stack with local images (uses docker-stack.local.yml)"
	@echo "  force-update          Force rolling update of both services"
	@echo "  ghcr-login            Login to GHCR (needs GHCR_PAT env)"
	@echo "  build-remote          Build+push agent+ui to $(REGISTRY) (TAG=$(TAG), PLATFORMS=$(PLATFORMS))"
	@echo "  build-agent-remote    Build+push agent only"
	@echo "  build-ui-remote       Build+push ui only"
	@echo "  deploy-remote         Deploy stack from registry images (REGISTRY/OWNER/TAG)"
	@echo "  show                  Show service status"

.PHONY: build-local build-agent-local build-ui-local
build-local: build-agent-local build-ui-local

build-agent-local:
	docker build -t firewall-agent:local -f firewall-agent/Dockerfile .

build-ui-local:
	docker build -t firewall-agent-ui:local -f firewall-agent-ui/Dockerfile .

.PHONY: deploy-local
deploy-local:
	docker stack deploy -c firewall-agent/docker-stack.yml -c firewall-agent/docker-stack.local.yml $(STACK)

.PHONY: force-update
force-update:
	-@docker service update --force $(SERV_AGENT)
	-@docker service update --force $(SERV_UI)

.PHONY: ghcr-login
ghcr-login:
	@[ -n "$$GHCR_PAT" ] || (echo "GHCR_PAT is required" && exit 1)
	@echo "Logging into $(REGISTRY) as $(OWNER)"
	@echo $$GHCR_PAT | docker login $(REGISTRY) -u $(OWNER) --password-stdin

.PHONY: build-remote build-agent-remote build-ui-remote
build-remote: build-agent-remote build-ui-remote

build-agent-remote:
	docker buildx build --platform $(PLATFORMS) -f firewall-agent/Dockerfile -t $(IMG_AGENT) . --push

build-ui-remote:
	docker buildx build --platform $(PLATFORMS) -f firewall-agent-ui/Dockerfile -t $(IMG_UI) . --push

.PHONY: deploy-remote
deploy-remote:
	REGISTRY=$(REGISTRY) OWNER=$(OWNER) TAG=$(TAG) docker stack deploy --with-registry-auth -c firewall-agent/docker-stack.yml $(STACK)

.PHONY: show
show:
	@echo "Services:"
	-@docker service ls | grep $(STACK) || true
	@echo "\nTasks (agent):"
	-@docker service ps $(SERV_AGENT) || true
	@echo "\nTasks (ui):"
	-@docker service ps $(SERV_UI) || true

