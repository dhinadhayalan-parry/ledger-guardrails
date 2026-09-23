# ADR 0003: The gate cannot be weakened by the change it judges

- Status: Accepted
- Date: 2026-09-24

## Context

A policy gate is only as strong as the path around it. In Phase 0 a pull request was evaluated with the policies, catalog and exemptions from its own branch, so a pull request that set a control to `warn`, deleted a rule, or added an exemption was judged by its own weakened rules and passed. The default branch had no protection, so a direct push skipped the gate entirely.

## Decisions

**Pull requests are gated by the base commit's rules.** For `pull_request` events CI checks out `policies/terraform`, `controls/` and `config/` from `github.event.pull_request.base.sha` into `.trusted/` and runs the gate with `POLICY_ROOT=.trusted`. A policy, catalog or exemption change therefore takes effect for the pull requests after it merges, never for itself. The proposed policies are still exercised in the same pull request by the unit tests, the non-compliant example, and a second gate run of the compliant sandbox stack, so a policy change that would reject the reference stack fails before merge.

**Exemptions are data, reviewed and merged separately.** `config/exemptions.yaml` downgrades one finding (control, resource address, environment) to a warning that stays visible in the output, until `expires_on`. The gate honours only controls the catalog marks `exemptible: true` (currently LG-BCP-02), requires a ticket, and ignores expired or unparsable dates, so every malformed exemption fails closed. `scripts/traceability.py` rejects malformed entries and expiries more than 30 days ahead, and reports expired entries without failing unrelated builds. Because the gate reads exemptions from the base commit, an exemption and the change it covers are two reviews: the exemption merges first.

**The default branch is protected by a ruleset, managed as code.** `governance/github` defines a ruleset for the default branch: pull request required, the policy jobs required and pinned to the GitHub Actions app so a status posted by another integration cannot satisfy them, branch up to date before merge, no force-push, no deletion, no bypass actors. It also defines the `plan` environment whose required reviewer approves each OIDC plan run, because `terraform plan` executes pull request code (providers, external data sources) while holding the plan identity's token.

**Everything the gate depends on is code-owned.** CODEOWNERS covers `controls/`, `policies/`, `config/`, `scripts/`, `Makefile`, `.github/` and `governance/`.

## Consequences

- A change that tightens a policy needs two merges before infrastructure is judged by it. That is the intended ordering.
- The workflow, Makefile and scripts still run from the pull request head; GitHub offers no way for a personal repository to pin them to the base branch (required workflows are an organisation feature). Tampering with them is caught by review: CODEOWNERS plus the ruleset. With a single maintainer that review is not independent. Setting `required_approvals` to 1 or more in `governance/github` once a second maintainer exists turns on code owner review and last-push approval.
- The ruleset can be applied by hand first. Once the module is applied with `existing_ruleset_id`, the hand-made ruleset is imported, and later changes go through code review.
