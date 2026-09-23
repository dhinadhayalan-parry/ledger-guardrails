# ADR 0002: Plan-time policy conventions and their limits

- Status: Accepted
- Date: 2026-09-24

## Context

Rego policies evaluate the JSON from `terraform show -json <planfile>`. That document has sharp edges: values that are unknown until apply, nested blocks rendered as lists, and resources that are being deleted. Each policy has to handle them the same way, or the gate becomes inconsistent.

## Decisions

**Evaluate creates and updates only.** `lib.changes` selects managed resources whose actions include `create` or `update`. A replacement (`delete` + `create`) is included. A pure delete is ignored by the hardening policies, so a PR that removes a non-compliant resource is never blocked by them. Deletion itself is governed by one dedicated package, `protection.rego` (LG-BCP-02), which blocks destroying or replacing Key Vaults, keys and unclassified or sensitive data stores unless an exemption was merged first (ADR 0003).

**Security-relevant computed attributes must be explicit.** Attributes such as `public_network_access` on storage or `public_network_access_enabled` on Key Vault and PostgreSQL are optional and computed. When they are omitted, the plan shows them as unknown and the key is absent from `after`. A check like `after.x != "Disabled"` then never fires. Policies are written as `not after.x == <safe value>`, which fails when the value is unknown. The message tells the author to set the value explicitly. Relying on the provider's default is how insecure defaults slip through.

**Negated checks on nested blocks use `lib.nested_is`.** In Rego, `not lib.block(after, "authentication").password_auth_enabled == false` is undefined, so it never fires, when the block is missing: OPA pulls the function call out of the negation. The helper `nested_is(after, block, attr, value)` returns a plain boolean that is safe to negate. A unit test caught this during development. The tests for a missing `authentication` block and an empty RBAC block now cover it.

**Customer-managed keys on storage use the inline block.** The standalone `azurerm_storage_account_customer_managed_key` resource references the account by ID, which is unknown at plan time for a new account, so a plan-time policy cannot reliably link the two. This repository standardises on the inline `customer_managed_key` block. The limitation disappears at the Azure Policy layer, which evaluates the deployed resource.

**An unknown data class is the strictest class.** If `tags`, or only its `data-class` value, is computed from values known after apply, it is absent from `after` and marked in `after_unknown`. `lib.data_class` then returns `payment`, so the data controls (customer-managed keys, geo-redundant backups) still apply and a computed tag cannot switch them off. A fully hardened resource passes. `tags.rego` counts an individually unknown tag as present. A tag map that is unknown as a whole cannot be checked for completeness at plan time; the Azure Policy tag rules in Phase 1 close that gap.

**The mode comes from the catalog, not the policy.** Policies only emit findings. `gate.rego` maps each finding to `deny` or `warn` using `controls.<id>.mode.<env>`. An unknown environment is treated as `prod`, and a control missing from the catalog is enforced, so a configuration mistake cannot make the gate fail open.

## Offline plans

Every pull request, including those from forks, gets the gate evaluated against a real `terraform plan` of the real code, without cloud credentials. `scripts/mock_arm.py` serves only the Azure metadata document and an unsigned token, the two things the azurerm provider needs to plan with `-refresh=false` and no state. Any other request returns 501, and `scripts/offline_plan.sh` fails if the mock logs one, so a provider upgrade that starts calling APIs during plan breaks the job loudly instead of producing a misleading plan.

The offline plan does not see existing resources, so it plans everything as a create. The OIDC plan against the real subscription stays the authoritative gate before apply.

## Consequences

- Authors write a few more explicit attributes than the provider requires. That is intended.
- The azurerm provider is pinned to a major version (`~> 5.6`). A major upgrade renames attributes, so it needs a policy review. The unit tests and the non-compliant example break visibly when an attribute the policies rely on changes.
