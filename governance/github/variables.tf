variable "owner" {
  description = "GitHub user or organisation that owns the repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", var.owner))
    error_message = "owner must be a valid GitHub login."
  }
}

variable "repository" {
  description = "Repository name, without the owner."
  type        = string
  default     = "ledger-guardrails"
}

variable "plan_reviewers" {
  description = "GitHub logins that must approve a run of the OIDC plan job before it receives an Azure token."
  type        = set(string)

  validation {
    condition     = length(var.plan_reviewers) > 0 && length(var.plan_reviewers) <= 6
    error_message = "plan_reviewers needs between 1 and 6 logins (GitHub's limit for required reviewers)."
  }
}

variable "required_approvals" {
  description = <<-EOT
    Approving reviews required on pull requests to the default branch. 0 suits a
    single-maintainer repository, where the author cannot approve their own pull
    request; set 1 or more once there is a second maintainer, which also turns
    on code owner review and last-push approval.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.required_approvals >= 0 && var.required_approvals <= 6 && floor(var.required_approvals) == var.required_approvals
    error_message = "required_approvals must be a whole number from 0 to 6."
  }
}

variable "required_checks" {
  description = "CI job names that must pass before merging. Must match the job `name:` values in .github/workflows/policy-gate.yml."
  type        = set(string)
  default = [
    "Policy tests and traceability",
    "Gate on offline plan (no credentials)",
  ]
}

variable "existing_ruleset_id" {
  description = "ID of a ruleset created by hand in the UI, to import instead of creating a duplicate. Leave null for a new ruleset."
  type        = number
  default     = null
}
