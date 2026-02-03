# AGENTS.md

Guidelines for AI agent collaboration on this repository.

## Overview

This project uses AI agents (Claude Code) to assist with development. Multiple agents may work in parallel, each with assigned roles. See [CLAUDE.md](CLAUDE.md) for agent-specific instructions.

## Agent Roles

| Role | Abbreviation | Responsibilities |
|------|--------------|------------------|
| Lead Software Developer | LSD | Code review, architecture decisions, technical leadership |
| Lead Systems Engineer | LSE | Core implementation, architecture, Bash scripts |
| Documentation Engineer | Doc | README, docs/, guides, CHANGELOG |
| Windows Developer | Win | PowerShell scripts, Windows compatibility |
| QA Engineer | QA | Testing, validation, coverage |

## PR Workflow for Solo Maintainers

### The Problem

When AI agents create pull requests on behalf of a solo maintainer:

1. The PR is authored by the maintainer's GitHub account
2. GitHub prevents users from approving their own PRs
3. Branch protection requires at least one approval
4. Result: **Merge blocked**

This was encountered with PR #9 (PowerShell test infrastructure).

### Solutions

#### Option 1: Admin Merge (Recommended for Solo Maintainers)

Repository admins can merge PRs without required approvals if configured:

1. **Disable "Include administrators"** in branch protection settings
2. Admin can then merge PRs that pass CI, bypassing the approval requirement

```bash
# Check current protection settings
gh api repos/{owner}/{repo}/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  | jq '.enforce_admins'

# If enforce_admins.enabled is true, admin bypass is disabled
```

To disable admin enforcement (allows admin to bypass):
```bash
gh api repos/{owner}/{repo}/branches/main/protection/enforce_admins \
  -X DELETE \
  -H "Accept: application/vnd.github+json"
```

#### Option 2: GitHub App for Reviews

Use a GitHub App or bot account to provide reviews:

1. Create a GitHub App with `pull_request` write permissions
2. Configure it to auto-approve PRs that pass CI
3. The app's approval counts toward the required review count

**Pros:** Maintains audit trail, automated
**Cons:** Setup complexity, may not satisfy compliance requirements

#### Option 3: Temporary Protection Disable

For occasional use:

```bash
# Disable protection temporarily
gh api repos/{owner}/{repo}/branches/main/protection \
  -X DELETE \
  -H "Accept: application/vnd.github+json"

# Merge the PR
gh pr merge <PR_NUMBER> --squash

# Re-enable protection
# (Re-run your protection setup script or use the web UI)
```

**Warning:** This creates a window where anyone can push to main.

#### Option 4: Second GitHub Account

Create a separate GitHub account for AI agent work:

1. AI agents push branches from this account
2. Main maintainer account reviews and approves
3. Requires managing multiple accounts

### Recommended Workflow

For solo maintainers using AI agents:

1. **AI agent creates PR** from feature branch
2. **AI agent (different role) reviews** and comments in PR
3. **Maintainer verifies** CI passes and review is thorough
4. **Maintainer merges** using admin privileges (Option 1)

This maintains:
- Code review discipline (AI reviews are documented)
- CI validation (all checks must pass)
- Audit trail (PR history preserved)

### Branch Protection Settings for Solo Maintainers

Recommended settings in `.github/settings.yml` or via API:

```yaml
branches:
  - name: main
    protection:
      required_pull_request_reviews:
        required_approving_review_count: 1
        dismiss_stale_reviews: true
      required_status_checks:
        strict: true
        contexts:
          - "ShellCheck"
          - "Tests (Ubuntu)"
          - "Tests (macOS)"
      enforce_admins: false  # Allows admin merge without approval
      restrictions: null
```

## Agent Coordination

### Identifying Active Agents

Each agent sets a terminal tab title on session start:

```bash
echo -ne "\033]0;Lead Systems Engineer\007"
```

Agents sign off responses with their role:
```
— Windows Developer
```

### Task Handoffs

When one agent needs another to continue work:

1. Create a task with clear description
2. Note any blockers or dependencies
3. The next agent picks up from the task list

Example:
```
Task: Review PR #9 before merge
Blocked by: Needs LSD approval
```

### Avoiding Conflicts

- Only one agent should edit a file at a time
- Use feature branches for parallel work
- Coordinate via task list and chat

## Related Documentation

- [CLAUDE.md](CLAUDE.md) - AI agent instructions
- [docs/BRANCH-PROTECTION.md](docs/BRANCH-PROTECTION.md) - Branch protection setup
- [docs/TESTING.md](docs/TESTING.md) - Test requirements before merging
