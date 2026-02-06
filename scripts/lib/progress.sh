#!/bin/bash
#
# Progress Indicator Library
#
# Purpose: Shared progress display functions for long-running scan scripts
# NIST Controls:
#   - AU-3 (Content of Audit Records): User feedback during operations
#
# Usage:
#   source "$SCRIPT_DIR/lib/progress.sh"
#   spinner_start "Updating database"
#   # ... long operation ...
#   spinner_stop
#
#   progress_bar 45 100 "Scanning files"
#   # Output: Scanning files: [████████████░░░░░░░░░░░░░] 45%
#
# Features:
#   - Spinner for indeterminate operations
#   - Progress bar for countable operations
#   - Elapsed time display
#   - ETA calculation
#   - TTY detection (no progress on non-interactive)

# Check if output is a terminal (interactive)
PROGRESS_IS_TTY=0
if [ -t 1 ]; then
    PROGRESS_IS_TTY=1
fi

# Spinner state
SPINNER_PID=""
SPINNER_MSG=""

# Progress bar width
PROGRESS_BAR_WIDTH=25

# Start time for elapsed calculations
PROGRESS_START_TIME=""

# ============================================================================
# SPINNER FUNCTIONS (for indeterminate operations)
# ============================================================================

# Start a spinner with optional message
# Usage: spinner_start "Loading..."
spinner_start() {
    local msg="${1:-Working}"
    SPINNER_MSG="$msg"

    # Only show spinner on TTY
    if [ "$PROGRESS_IS_TTY" -ne 1 ]; then
        echo "$msg..."
        return
    fi

    # Kill any existing spinner
    spinner_stop 2>/dev/null

    # Start spinner in background
    (
        local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        local i=0
        while true; do
            printf "\r%s %s " "$msg" "${chars:$i:1}"
            i=$(( (i + 1) % ${#chars} ))
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!

    # Ensure cleanup on script exit (append to existing EXIT trap)
    local existing_trap
    existing_trap=$(trap -p EXIT | sed "s/^trap -- '//;s/' EXIT$//" || true)
    if [ -n "$existing_trap" ]; then
        trap "${existing_trap}; spinner_stop 2>/dev/null" EXIT
    else
        trap 'spinner_stop 2>/dev/null' EXIT
    fi
}

# Stop the spinner
# Usage: spinner_stop [status_message]
spinner_stop() {
    local status="${1:-done}"

    if [ -n "$SPINNER_PID" ]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
        SPINNER_PID=""
    fi

    if [ "$PROGRESS_IS_TTY" -eq 1 ]; then
        # Clear spinner line and show status
        printf "\r%-60s\r" " "
        if [ -n "$SPINNER_MSG" ]; then
            echo "$SPINNER_MSG... $status"
        fi
    fi
    SPINNER_MSG=""
}

# ============================================================================
# PROGRESS BAR FUNCTIONS (for countable operations)
# ============================================================================

# Display a progress bar
# Usage: progress_bar current total [message]
# Example: progress_bar 45 100 "Scanning files"
progress_bar() {
    local current="$1"
    local total="$2"
    local msg="${3:-Progress}"

    # Validate inputs
    if [ -z "$current" ] || [ -z "$total" ] || [ "$total" -eq 0 ]; then
        return
    fi

    # Calculate percentage
    local percent=$((current * 100 / total))

    # Only show on TTY
    if [ "$PROGRESS_IS_TTY" -ne 1 ]; then
        # Non-TTY: show milestone updates only (every 25%)
        case "$percent" in
            25|50|75|100)
                echo "$msg: $percent% ($current/$total)"
                ;;
        esac
        return
    fi

    # Calculate filled/empty portions
    local filled=$((percent * PROGRESS_BAR_WIDTH / 100))
    local empty=$((PROGRESS_BAR_WIDTH - filled))

    # Build bar string
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    # Calculate ETA if we have start time
    local eta=""
    if [ -n "$PROGRESS_START_TIME" ] && [ "$current" -gt 0 ]; then
        local elapsed=$(($(date +%s) - PROGRESS_START_TIME))
        if [ "$elapsed" -gt 2 ] && [ "$percent" -gt 0 ] && [ "$percent" -lt 100 ]; then
            local total_estimated=$((elapsed * 100 / percent))
            local remaining=$((total_estimated - elapsed))
            if [ "$remaining" -gt 60 ]; then
                eta=" ETA: $((remaining / 60))m $((remaining % 60))s"
            elif [ "$remaining" -gt 0 ]; then
                eta=" ETA: ${remaining}s"
            fi
        fi
    fi

    # Print progress bar (carriage return to overwrite)
    printf "\r%s: [%s] %3d%% (%d/%d)%s" "$msg" "$bar" "$percent" "$current" "$total" "$eta"

    # Newline at 100%
    if [ "$percent" -ge 100 ]; then
        echo ""
    fi
}

# Start progress tracking (records start time)
# Usage: progress_start
progress_start() {
    PROGRESS_START_TIME=$(date +%s)
}

# End progress tracking and show final status
# Usage: progress_end [message]
progress_end() {
    local msg="${1:-Complete}"

    if [ "$PROGRESS_IS_TTY" -eq 1 ]; then
        printf "\r%-70s\r" " "
    fi

    if [ -n "$PROGRESS_START_TIME" ]; then
        local elapsed=$(($(date +%s) - PROGRESS_START_TIME))
        local elapsed_str
        if [ "$elapsed" -ge 60 ]; then
            elapsed_str="$((elapsed / 60))m $((elapsed % 60))s"
        else
            elapsed_str="${elapsed}s"
        fi
        echo "$msg (${elapsed_str})"
    else
        echo "$msg"
    fi

    PROGRESS_START_TIME=""
}

# ============================================================================
# STEP PROGRESS (for multi-step operations)
# ============================================================================

# Show step progress
# Usage: progress_step current total step_name
# Example: progress_step 2 6 "Running PII scan"
progress_step() {
    local current="$1"
    local total="$2"
    local step_name="$3"

    if [ "$PROGRESS_IS_TTY" -eq 1 ]; then
        echo ""
        echo "[$current/$total] $step_name"
    else
        echo "[$current/$total] $step_name"
    fi
}

# ============================================================================
# STATUS LINE (inline status updates)
# ============================================================================

# Show a status line that can be overwritten
# Usage: status_line "Checking file.txt..."
status_line() {
    local msg="$1"

    if [ "$PROGRESS_IS_TTY" -eq 1 ]; then
        printf "\r%-70s\r%s" " " "$msg"
    fi
}

# Clear the status line
# Usage: status_clear
status_clear() {
    if [ "$PROGRESS_IS_TTY" -eq 1 ]; then
        printf "\r%-70s\r" " "
    fi
}

# ============================================================================
# ELAPSED TIME
# ============================================================================

# Format seconds as human-readable time
# Usage: format_elapsed 125  # Returns "2m 5s"
format_elapsed() {
    local seconds="$1"

    if [ "$seconds" -ge 3600 ]; then
        echo "$((seconds / 3600))h $((seconds % 3600 / 60))m"
    elif [ "$seconds" -ge 60 ]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    else
        echo "${seconds}s"
    fi
}

# Show elapsed time since progress_start
# Usage: show_elapsed "Scan"
show_elapsed() {
    local label="${1:-Elapsed}"

    if [ -n "$PROGRESS_START_TIME" ]; then
        local elapsed=$(($(date +%s) - PROGRESS_START_TIME))
        echo "$label: $(format_elapsed $elapsed)"
    fi
}
