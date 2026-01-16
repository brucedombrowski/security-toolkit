#!/bin/bash
#
# Pre-Scan/Remediation Backup Guidance
#
# Purpose: Display backup guidance before security scanning or remediation
# Method: Informational script with platform-specific backup instructions
#
# Best Practice:
#   ALWAYS create a full system backup before:
#   1. Running security scans that might modify system state
#   2. Performing any remediation actions
#   3. Installing security tools or updates
#   4. Making configuration changes
#
# Standards:
#   - NIST SP 800-53: CP-9 (System Backup)
#   - NIST SP 800-53: CP-10 (System Recovery and Reconstitution)
#   - NIST SP 800-34: Contingency Planning Guide
#
# Usage: ./backup-guidance.sh [OPTIONS]
#        -c, --check     Check current backup status
#        -q, --quiet     Minimal output
#        -h, --help      Show this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Help function
show_help() {
    cat << 'EOF'
Usage: backup-guidance.sh [OPTIONS]

Display backup guidance before security scanning or remediation.
Creating a system image before security work ensures you can recover
if something goes wrong.

OPTIONS:
  -c, --check     Check current backup status (Time Machine, etc.)
  -q, --quiet     Minimal output (just status)
  -h, --help      Show this help message

WHY BACKUP BEFORE SCANNING/REMEDIATION?

  1. Security scans may trigger system changes
  2. Remediation actions modify configurations
  3. False positives could lead to removing needed files
  4. Security tool installation may conflict with existing software
  5. System state can be restored if issues occur

BACKUP RECOMMENDATIONS BY PLATFORM:

  macOS:
    - Time Machine (built-in, automatic)
    - Carbon Copy Cloner (bootable clone)
    - SuperDuper! (bootable clone)

  Linux:
    - Timeshift (system restore points)
    - Borg Backup (deduplicating backup)
    - Clonezilla (disk imaging)

  Windows:
    - System Restore Point
    - File History
    - Windows Backup
    - Macrium Reflect (disk imaging)

NIST CONTROLS:
  CP-9   System Backup
  CP-10  System Recovery and Reconstitution

EOF
    exit 0
}

# Check backup status
check_backup_status() {
    echo ""
    echo -e "${BLUE}Checking Backup Status...${NC}"
    echo "========================================"

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS - Check Time Machine
        echo ""
        echo -e "${BLUE}Time Machine Status:${NC}"
        if command -v tmutil >/dev/null 2>&1; then
            # Destination info
            dest_info=$(tmutil destinationinfo 2>/dev/null || echo "Not configured")
            if echo "$dest_info" | grep -q "Name"; then
                dest_name=$(echo "$dest_info" | grep "Name" | head -1 | awk -F': ' '{print $2}')
                echo -e "  Destination: ${GREEN}$dest_name${NC}"
            else
                echo -e "  Destination: ${RED}Not configured${NC}"
            fi

            # Last backup
            last_backup=$(tmutil latestbackup 2>/dev/null || echo "")
            if [ -n "$last_backup" ]; then
                backup_date=$(basename "$last_backup")
                echo -e "  Last Backup: ${GREEN}$backup_date${NC}"

                # Check if backup is recent (within 24 hours)
                backup_epoch=$(date -j -f "%Y-%m-%d-%H%M%S" "$backup_date" "+%s" 2>/dev/null || echo "0")
                now_epoch=$(date "+%s")
                hours_ago=$(( (now_epoch - backup_epoch) / 3600 ))

                if [ "$hours_ago" -lt 24 ]; then
                    echo -e "  Age: ${GREEN}$hours_ago hours ago (recent)${NC}"
                elif [ "$hours_ago" -lt 168 ]; then
                    echo -e "  Age: ${YELLOW}$hours_ago hours ago (consider backing up)${NC}"
                else
                    echo -e "  Age: ${RED}$hours_ago hours ago (backup recommended!)${NC}"
                fi
            else
                echo -e "  Last Backup: ${RED}No backups found${NC}"
            fi

            # Backup status
            status=$(tmutil status 2>/dev/null | grep "Running" | awk -F'= ' '{print $2}' | tr -d ';')
            if [ "$status" = "1" ]; then
                echo -e "  Status: ${YELLOW}Backup in progress...${NC}"
            else
                echo -e "  Status: Idle"
            fi
        else
            echo -e "  ${RED}tmutil not available${NC}"
        fi

        # Check for other backup software
        echo ""
        echo -e "${BLUE}Other Backup Software:${NC}"

        if [ -d "/Applications/Carbon Copy Cloner.app" ]; then
            echo -e "  Carbon Copy Cloner: ${GREEN}Installed${NC}"
        fi

        if [ -d "/Applications/SuperDuper!.app" ]; then
            echo -e "  SuperDuper!: ${GREEN}Installed${NC}"
        fi

        if [ -d "/Applications/Arq.app" ] || [ -d "/Applications/Arq 7.app" ]; then
            echo -e "  Arq Backup: ${GREEN}Installed${NC}"
        fi

        if [ -d "/Applications/Backblaze.app" ]; then
            echo -e "  Backblaze: ${GREEN}Installed${NC}"
        fi

    elif [[ "$(uname)" == "Linux" ]]; then
        # Linux backup checks
        echo ""
        echo -e "${BLUE}Backup Tools:${NC}"

        if command -v timeshift >/dev/null 2>&1; then
            echo -e "  Timeshift: ${GREEN}Installed${NC}"
            # Try to get snapshot info
            snapshots=$(timeshift --list 2>/dev/null | grep -c "^[0-9]" || echo "0")
            echo "    Snapshots: $snapshots"
        else
            echo -e "  Timeshift: ${YELLOW}Not installed${NC}"
        fi

        if command -v borg >/dev/null 2>&1; then
            echo -e "  Borg Backup: ${GREEN}Installed${NC}"
        else
            echo -e "  Borg Backup: ${YELLOW}Not installed${NC}"
        fi

        if command -v restic >/dev/null 2>&1; then
            echo -e "  Restic: ${GREEN}Installed${NC}"
        else
            echo -e "  Restic: ${YELLOW}Not installed${NC}"
        fi

        if command -v rsync >/dev/null 2>&1; then
            echo -e "  rsync: ${GREEN}Available${NC}"
        fi
    fi

    echo ""
    echo "========================================"
}

# Show full guidance
show_guidance() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}           ${YELLOW}BACKUP GUIDANCE - Before Scanning/Remediation${NC}                 ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}IMPORTANT:${NC} Always create a full system backup before:"
    echo "  • Running security scans that might modify system state"
    echo "  • Performing any remediation actions"
    echo "  • Installing security tools or updates"
    echo "  • Making system configuration changes"
    echo ""

    if [[ "$(uname)" == "Darwin" ]]; then
        echo -e "${BLUE}macOS Backup Options:${NC}"
        echo ""
        echo "  1. Time Machine (Built-in, Recommended)"
        echo "     ─────────────────────────────────────"
        echo "     • System Preferences → Time Machine → Back Up Now"
        echo "     • Or from menu bar: Time Machine icon → Back Up Now"
        echo "     • CLI: tmutil startbackup --auto"
        echo ""
        echo "  2. Bootable Clone (Carbon Copy Cloner or SuperDuper!)"
        echo "     ─────────────────────────────────────────────────"
        echo "     • Creates a bootable copy of your entire drive"
        echo "     • Can boot from clone if main drive fails"
        echo "     • Best for pre-remediation snapshots"
        echo ""
        echo "  3. APFS Snapshot (Quick, Local)"
        echo "     ─────────────────────────────"
        echo "     • sudo tmutil localsnapshot"
        echo "     • Creates instant local snapshot"
        echo "     • Useful for quick rollback points"
        echo ""

    elif [[ "$(uname)" == "Linux" ]]; then
        echo -e "${BLUE}Linux Backup Options:${NC}"
        echo ""
        echo "  1. Timeshift (System Restore Points)"
        echo "     ─────────────────────────────────"
        echo "     • sudo timeshift --create --comments 'Pre-scan backup'"
        echo "     • Install: sudo apt install timeshift"
        echo "     • Best for system file snapshots"
        echo ""
        echo "  2. Borg Backup (Deduplicating)"
        echo "     ────────────────────────────"
        echo "     • borg create /backup::pre-scan-\$(date +%Y%m%d) /"
        echo "     • Install: sudo apt install borgbackup"
        echo "     • Efficient, encrypted backups"
        echo ""
        echo "  3. Clonezilla (Full Disk Image)"
        echo "     ─────────────────────────────"
        echo "     • Boot from Clonezilla USB"
        echo "     • Creates exact disk image"
        echo "     • Best for bare-metal recovery"
        echo ""
        echo "  4. rsync (File-level Backup)"
        echo "     ──────────────────────────"
        echo "     • rsync -avz --exclude=/proc --exclude=/sys / /backup/"
        echo "     • Available on all Linux systems"
        echo ""
    fi

    echo -e "${BLUE}Pre-Scan Checklist:${NC}"
    echo ""
    echo "  [ ] Full system backup completed"
    echo "  [ ] Backup verified (can be restored)"
    echo "  [ ] Backup stored on separate media/location"
    echo "  [ ] Critical data identified and backed up"
    echo "  [ ] Recovery plan documented"
    echo ""

    echo -e "${BLUE}NIST Compliance:${NC}"
    echo ""
    echo "  CP-9  System Backup"
    echo "        • Conduct backups of system-level information"
    echo "        • Test backup reliability and integrity"
    echo ""
    echo "  CP-10 System Recovery and Reconstitution"
    echo "        • Provide for system recovery to known state"
    echo "        • Reconstitute system within defined time period"
    echo ""

    echo -e "${YELLOW}Recommendation:${NC} Run backup verification before proceeding with scans."
    echo ""
}

# Parse arguments
CHECK_ONLY=0
QUIET=0

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -c|--check)
            CHECK_ONLY=1
            shift
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h for help"
            exit 1
            ;;
    esac
done

# Main execution
if [ "$CHECK_ONLY" -eq 1 ]; then
    check_backup_status
else
    if [ "$QUIET" -eq 0 ]; then
        show_guidance
    fi
    check_backup_status

    echo ""
    echo -e "${YELLOW}Would you like to proceed with security scans? (y/N)${NC} "
    echo -e "${BLUE}Tip: Run 'tmutil startbackup --auto' first if you haven't backed up recently.${NC}"
    echo ""
fi

exit 0
