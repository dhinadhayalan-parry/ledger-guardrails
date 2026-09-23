output "ruleset_id" {
  description = "ID of the default branch ruleset."
  value       = github_repository_ruleset.default_branch.ruleset_id
}

output "plan_environment" {
  description = "Environment that gates the OIDC plan job."
  value       = github_repository_environment.plan.environment
}
