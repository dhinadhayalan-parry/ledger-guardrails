SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := all

ENV ?= sandbox
BUILD := build
TF_POLICY := policies/terraform
TF_ROOTS := infra/envs/sandbox examples/noncompliant
CONFTEST_DATA := --data controls/catalog.yaml --data config/envs/$(ENV).yaml

ifeq ($(filter $(ENV),sandbox prod),)
$(error ENV must be sandbox or prod, got '$(ENV)')
endif

.PHONY: all test rego-test admission-test trace matrix validate plans gate examples clean

all: test trace validate examples gate ## Everything CI runs, except the OIDC plan

test: rego-test admission-test ## Policy unit tests

rego-test:
	opa fmt --fail --list $(TF_POLICY)
	opa check --strict $(TF_POLICY)
	opa test $(TF_POLICY) --coverage --threshold 100 --format json > /dev/null \
		|| { opa test $(TF_POLICY) --verbose; exit 1; }
	opa test $(TF_POLICY)

admission-test:
	gator verify ./policies/kubernetes/...

trace: ## Catalog <-> policy traceability and README freshness
	python3 scripts/traceability.py

matrix: ## Regenerate the README control matrix
	python3 scripts/traceability.py --write-readme

validate: ## terraform fmt and validate for every root module
	terraform fmt -check -recursive infra examples
	for dir in $(TF_ROOTS); do \
		terraform -chdir=$$dir init -backend=false -input=false -lockfile=readonly > /dev/null; \
		terraform -chdir=$$dir validate -no-color; \
	done

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sandbox.plan.json: $(wildcard infra/envs/sandbox/*.tf) infra/envs/sandbox/offline-plan.tfvars | $(BUILD)
	scripts/offline_plan.sh infra/envs/sandbox $@ infra/envs/sandbox/offline-plan.tfvars

$(BUILD)/noncompliant.plan.json: $(wildcard examples/noncompliant/*.tf) | $(BUILD)
	scripts/offline_plan.sh examples/noncompliant $@

plans: $(BUILD)/sandbox.plan.json $(BUILD)/noncompliant.plan.json ## Offline plans (no Azure credentials)

gate: $(BUILD)/sandbox.plan.json ## Evaluate the sandbox plan for ENV=sandbox|prod
	conftest test $< --policy $(TF_POLICY) $(CONFTEST_DATA) --no-color

examples: $(BUILD)/noncompliant.plan.json ## The bad PR must fail with exactly the expected findings
	conftest test $< --policy $(TF_POLICY) --data controls/catalog.yaml --data config/envs/sandbox.yaml \
		--output json > $(BUILD)/noncompliant.results.json || true
	jq -r '.[].failures[]?.msg' $(BUILD)/noncompliant.results.json | LC_ALL=C sort > $(BUILD)/noncompliant.denies.txt
	diff -u examples/noncompliant/expected-denies.txt $(BUILD)/noncompliant.denies.txt
	@echo "examples: non-compliant plan rejected with the $$(wc -l < $(BUILD)/noncompliant.denies.txt) expected findings"

clean:
	rm -rf $(BUILD)
	find infra examples -type d -name .terraform -prune -exec rm -rf {} +
