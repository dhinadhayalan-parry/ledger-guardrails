# ADR 0001: Enforce the same control at several layers

- Status: Accepted
- Date: 2026-09-24

## Context

Ledger's controls come from ISO 27001, SOC 2 and the CIS Azure benchmark. A control only counts if it holds on every path a change can take into production:

1. a Terraform pull request
2. a change made directly in the portal, the CLI or by another tool
3. a workload deployed into AKS
4. drift on a running resource or host after deployment

No single tool sees all four paths.

## Decision

Write each control once in `controls/catalog.yaml` and enforce it at the layers that can see it:

| Layer | Tool | Sees path | Nature |
|---|---|---|---|
| Pull request | OPA/Rego on `terraform show -json`, via conftest | 1 | Preventive, feedback in seconds, explains the fix |
| Azure control plane (Phase 1) | Azure Policy `Deny`, `Modify`, `DeployIfNotExists` at management group scope | 1, 2 | Preventive and cannot be bypassed, but feedback comes late |
| Cluster admission | Gatekeeper templates through the AKS Azure Policy add-on | 3 | Preventive inside Kubernetes |
| Runtime (Phase 3) | cnspec scans, Terraform drift detection | 4 | Detective |

The catalog records which layers enforce each control, and `scripts/traceability.py` keeps the catalog and the code in sync.

## Why both the PR gate and Azure Policy

They are not duplicates.

- Azure Policy is the backstop. It stops portal and CLI changes that Terraform never sees. But a developer only hears about a violation when `terraform apply` fails, after review and merge.
- The PR gate gives feedback on the pull request itself, with a message that names the control and the fix. It cannot see changes made outside Terraform.

## Alternatives considered

- **Azure Policy only.** Simpler, but developers lose fast feedback and the review conversation happens after merge.
- **Off-the-shelf scanners only (Checkov, Trivy config).** They enforce generic best practice well and are worth running alongside. They do not encode this organisation's own requirements, such as the data classification that decides whether a customer-managed key is required, and they do not link a failure back to a control ID an auditor can trace.
- **Kyverno or ValidatingAdmissionPolicy (CEL) for admission.** Kyverno is easier for application teams to read. CEL needs no webhook to operate. Gatekeeper templates were chosen because AKS ships a managed Gatekeeper with the Azure Policy add-on, which reports compliance in the same place as the Azure resources, and because it keeps a single policy language (Rego) across both layers.

## Consequences

- One control can fail at two layers with slightly different wording. Every message carries the control ID, so both point to the same requirement.
- The Azure Policy add-on syncs policy changes to the cluster with a delay of several minutes. A new admission policy therefore reaches clusters minutes after its assignment, not seconds.
- Admission is enforced on Pods, so every controller is covered. The trade-off is that a rejected Deployment shows up as a ReplicaSet event, not as a `kubectl apply` error.
