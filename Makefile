SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := all

ENV ?= sandbox
BUILD := build
TF_POLICY := policies/terraform
TF_ROOTS := infra/envs/sandbox examples/noncompliant
# Root modules whose provider lockfile is not committed yet: validated, but the
# lockfile is resolved fresh. Move a root to TF_ROOTS once its lockfile exists.
TF_ROOTS_UNLOCKED := governance/github
# Where the gate reads policies, catalog and exemptions from. CI points this at
# a checkout of the pull request's base commit, so a change cannot relax the
# rules it is judged by. Policy tests and examples always use the working tree.
POLICY_ROOT ?= .
# A missing exemptions file means no exemptions (fail closed).
GATE_DATA := --data $(POLICY_ROOT)/controls/catalog.yaml --data $(POLICY_ROOT)/config/envs/$(ENV).yaml \
	$(addprefix --data ,$(wildcard $(POLICY_ROOT)/config/exemptions.yaml))

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
	terraform fmt -check -recursive infra examples governance
	for dir in $(TF_ROOTS); do \
		terraform -chdir=$$dir init -backend=false -input=false -lockfile=readonly > /dev/null; \
		terraform -chdir=$$dir validate -no-color; \
	done
	for dir in $(TF_ROOTS_UNLOCKED); do \
		echo "WARNING: $$dir has no committed provider lockfile" >&2; \
		terraform -chdir=$$dir init -backend=false -input=false > /dev/null; \
		terraform -chdir=$$dir validate -no-color; \
		rm -f $$dir/.terraform.lock.hcl; \
	done

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sandbox.plan.json: $(wildcard infra/envs/sandbox/*.tf) infra/envs/sandbox/offline-plan.tfvars | $(BUILD)
	scripts/offline_plan.sh infra/envs/sandbox $@ infra/envs/sandbox/offline-plan.tfvars

$(BUILD)/noncompliant.plan.json: $(wildcard examples/noncompliant/*.tf) | $(BUILD)
	scripts/offline_plan.sh examples/noncompliant $@

plans: $(BUILD)/sandbox.plan.json $(BUILD)/noncompliant.plan.json ## Offline plans (no Azure credentials)

gate: $(BUILD)/sandbox.plan.json ## Evaluate the sandbox plan for ENV=sandbox|prod (POLICY_ROOT=<trusted checkout>)
	test -d "$(POLICY_ROOT)/$(TF_POLICY)" || { echo "POLICY_ROOT has no $(TF_POLICY): $(POLICY_ROOT)" >&2; exit 1; }
	conftest test $< --policy $(POLICY_ROOT)/$(TF_POLICY) $(GATE_DATA) --no-color

examples: $(BUILD)/noncompliant.plan.json ## The bad PR must fail with exactly the expected findings
	conftest test $< --policy $(TF_POLICY) --data controls/catalog.yaml --data config/envs/sandbox.yaml \
		--data config/exemptions.yaml --output json > $(BUILD)/noncompliant.results.json || true
	jq -r '.[].failures[]?.msg' $(BUILD)/noncompliant.results.json | LC_ALL=C sort > $(BUILD)/noncompliant.denies.txt
	diff -u examples/noncompliant/expected-denies.txt $(BUILD)/noncompliant.denies.txt
	@echo "examples: non-compliant plan rejected with the $$(wc -l < $(BUILD)/noncompliant.denies.txt) expected findings"

clean:
	rm -rf $(BUILD)
	find infra examples governance -type d -name .terraform -prune -exec rm -rf {} +
