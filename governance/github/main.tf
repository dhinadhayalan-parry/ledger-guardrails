locals {
  # The GitHub Actions app. Pinning required checks to it stops a status with
  # the same name posted by another app or token from satisfying the rule.
  github_actions_app_id = 15368

  reviews_required = var.required_approvals > 0
}

data "github_user" "plan_reviewers" {
  for_each = var.plan_reviewers
  username = each.value
}

# Protects the default branch: every change arrives through a pull request that
# passed the policy gate, and history cannot be rewritten or deleted.
resource "github_repository_ruleset" "default_branch" {
  name        = "default-branch-protection"
  repository  = var.repository
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  # No bypass actors: administrators follow the same rules.

  rules {
    deletion         = true
    non_fast_forward = true

    pull_request {
      required_approving_review_count   = var.required_approvals
      require_code_owner_review         = local.reviews_required
      require_last_push_approval        = local.reviews_required
      dismiss_stale_reviews_on_push     = true
      required_review_thread_resolution = true
    }

    required_status_checks {
      strict_required_status_checks_policy = true

      dynamic "required_check" {
        for_each = var.required_checks
        content {
          context        = required_check.value
          integration_id = local.github_actions_app_id
        }
      }
    }
  }
}

import {
  for_each = var.existing_ruleset_id == null ? [] : [var.existing_ruleset_id]
  to       = github_repository_ruleset.default_branch
  id       = "${var.repository}:${each.value}"
}

# The OIDC plan job runs pull request code while holding an Azure token, so a
# reviewer approves each run. The Azure federated credential for the plan
# identity must use the subject repo:<owner>/<repo>:environment:plan.
# Self-review is allowed only while the repository has a single maintainer.
resource "github_repository_environment" "plan" {
  repository          = var.repository
  environment         = "plan"
  can_admins_bypass   = false
  prevent_self_review = local.reviews_required

  reviewers {
    users = [for user in data.github_user.plan_reviewers : tonumber(user.id)]
  }
}
