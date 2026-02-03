#!/bin/bash
#
# Agent Role Management
#
# Purpose: Manage agent identification in multi-agent environments
# Usage: Source this file, then call assign_role "Role Name"
#
# Functions:
#   assign_role() - Set terminal title and export AGENT_ROLE
#   get_role() - Return current agent role
#   sign_off() - Print role signature for response endings
#
# Example:
#   source "$SCRIPT_DIR/lib/agent.sh"
#   assign_role "Lead Systems Engineer"
#   # ... do work ...
#   sign_off  # Prints: — Lead Systems Engineer

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    echo "Usage: source lib/agent.sh" >&2
    exit 1
fi

# Standard roles for this project (from CLAUDE.md)
readonly AGENT_ROLES=(
    "Lead Software Developer"
    "Lead Systems Engineer"
    "Documentation Engineer"
    "Windows Developer"
    "QA Engineer"
)

# Assign an agent role
# Usage: assign_role "Lead Systems Engineer"
# Effects:
#   - Sets terminal tab title
#   - Exports AGENT_ROLE environment variable
#   - Prints confirmation
assign_role() {
    local role="${1:-}"

    if [[ -z "$role" ]]; then
        echo "Usage: assign_role \"Role Name\"" >&2
        echo "" >&2
        echo "Standard roles:" >&2
        for r in "${AGENT_ROLES[@]}"; do
            echo "  - $r" >&2
        done
        return 1
    fi

    # Export role to environment
    export AGENT_ROLE="$role"

    # Set terminal tab title (works in most terminals)
    echo -ne "\033]0;${role}\007"

    # Confirmation
    echo "✓ Agent role assigned: $role"
    echo "  Terminal title updated"
    echo "  \$AGENT_ROLE exported"
}

# Get current agent role
# Returns: Current role or "Unassigned"
get_role() {
    echo "${AGENT_ROLE:-Unassigned}"
}

# Print role signature for response sign-off
# Usage: sign_off
# Output: — Lead Systems Engineer
sign_off() {
    local role
    role=$(get_role)

    if [[ "$role" == "Unassigned" ]]; then
        echo "Warning: No role assigned. Use assign_role first." >&2
        return 1
    fi

    echo ""
    echo "— $role"
}

# List available standard roles
list_roles() {
    echo "Standard agent roles:"
    for role in "${AGENT_ROLES[@]}"; do
        if [[ "${AGENT_ROLE:-}" == "$role" ]]; then
            echo "  ✓ $role (current)"
        else
            echo "    $role"
        fi
    done
}
