# Branch Protection Setup Guide

This document describes the branch protection settings for the `main` branch.

## Status

**Branch protection is ACTIVE** on `brucedombrowski/security-toolkit`.

Configured via GitHub API on 2026-02-02.

## Overview

Branch protection rules ensure code quality and prevent accidental pushes to the main branch.

## Recommended Settings

Navigate to **Settings → Branches → Branch protection rules → Add rule**

### Basic Settings

| Setting | Value | Rationale |
|---------|-------|-----------|
| Branch name pattern | `main` | Protects the primary branch |
| Require a pull request before merging | ✅ Enabled | All changes go through PR review |
| Require approvals | 1 | At least one reviewer must approve |
| Dismiss stale PR approvals when new commits are pushed | ✅ Enabled | Re-review after changes |

### Status Checks

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require status checks to pass before merging | ✅ Enabled | CI must pass |
| Require branches to be up to date before merging | ✅ Enabled | Prevents merge conflicts |

**Required status checks:**
- `ShellCheck` - Static analysis for shell scripts
- `Bash Syntax Check` - Validates script syntax
- `Tests (Ubuntu)` - Unit and integration tests on Linux
- `Tests (macOS)` - Unit and integration tests on macOS

### Additional Protection

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require conversation resolution before merging | ✅ Enabled | All review comments addressed |
| Require signed commits | Optional | Depends on team security requirements |
| Require linear history | Optional | Prevents merge commits (use squash/rebase) |
| Include administrators | ✅ Enabled | No bypass for anyone |

## Setup Instructions

### Via GitHub Web UI

1. Go to repository **Settings**
2. Click **Branches** in the left sidebar
3. Under "Branch protection rules", click **Add rule**
4. Enter `main` as the branch name pattern
5. Configure settings as described above
6. Click **Create** or **Save changes**

### Via GitHub CLI

```bash
# Note: Some settings require the web UI
gh api repos/{owner}/{repo}/branches/main/protection \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -f required_status_checks='{"strict":true,"contexts":["ShellCheck","Bash Syntax Check","Tests (Ubuntu)","Tests (macOS)"]}' \
  -f enforce_admins=true \
  -f required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \
  -f restrictions=null
```

## Workflow Integration

These branch protection settings work with the CI workflows:

| Workflow | File | Purpose |
|----------|------|---------|
| CI | `.github/workflows/ci.yml` | Runs on PRs and pushes to main |
| PR Checks | `.github/workflows/pr.yml` | Auto-labeling, title validation |
| Release | `.github/workflows/release.yml` | Automated releases on version tags |

## Bypassing Protection

In emergencies, repository administrators can bypass protection rules if "Include administrators" is disabled. However, this is discouraged.

For hotfixes:
1. Create a branch from `main`
2. Make the fix
3. Open a PR with `[HOTFIX]` prefix
4. Get expedited review
5. Merge normally

## Verification

To verify branch protection is active:

```bash
gh api repos/{owner}/{repo}/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  | jq '.required_status_checks, .required_pull_request_reviews'
```

## Related Documentation

- [GitHub Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)
- [CI Workflow](.github/workflows/ci.yml)
- [PR Workflow](.github/workflows/pr.yml)
