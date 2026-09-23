# governance/github

Repository controls that keep the policy gate from being bypassed (ADR 0003):

- **Default branch ruleset**: pull request required, both policy jobs required and pinned to the GitHub Actions app, branch up to date before merge, no force-push, no deletion, no bypass actors.
- **`plan` environment**: a required reviewer approves every OIDC plan run, because `terraform plan` executes pull request code while holding an Azure token.

CI validates this module but does not apply it. Applying it needs repository admin rights, which the pipeline deliberately does not have.

## Bootstrap by hand (once)

Until the module is applied, create the same ruleset in the UI: **Settings → Rules → Rulesets → New branch ruleset**.

| Setting | Value |
|---|---|
| Name | `default-branch-protection` |
| Enforcement status | Active |
| Bypass list | empty |
| Target branches | Include default branch |
| Restrict deletions | on |
| Block force pushes | on |
| Require a pull request before merging | on; required approvals `0` while there is a single maintainer; require conversation resolution; dismiss stale approvals |
| Require status checks to pass | on; require branches to be up to date; add `Policy tests and traceability` and `Gate on offline plan (no credentials)`, source **GitHub Actions** |

Then create the environment: **Settings → Environments → New environment** `plan`, enable **Required reviewers** with yourself, and leave **Allow administrators to bypass** off.

## Hand over to code

Prerequisites: the Terraform state storage from the workload (Phase 1) and a fine-grained personal access token limited to this repository with **Administration: read and write** and **Environments: read and write**, expiring within a day.

```bash
cd governance/github
export GITHUB_TOKEN='<fine-grained token>'   # read from your password manager; never commit it

# Commit the provider lockfile once, for CI and developer platforms.
terraform init -backend=false
terraform providers lock -platform=linux_amd64 -platform=darwin_arm64

terraform init \
  -backend-config="resource_group_name=<state rg>" \
  -backend-config="storage_account_name=<state account>" \
  -backend-config="container_name=<state container>" \
  -backend-config="key=ledger/github.tfstate"

# The ruleset ID is the number at the end of its URL in Settings → Rules → Rulesets.
terraform plan -out=tfplan \
  -var='owner=<github login>' \
  -var='plan_reviewers=["<github login>"]' \
  -var='existing_ruleset_id=<ruleset id>'
terraform apply tfplan
unset GITHUB_TOKEN
```

The first apply imports the hand-made ruleset. Once the lockfile is committed, move `governance/github` from `TF_ROOTS_UNLOCKED` to `TF_ROOTS` in the Makefile so CI validates it against the lockfile.

When a second maintainer joins, set `required_approvals = 1`. That also turns on code owner review, approval of the last push, and self-review prevention on the `plan` environment.
