# SSH TTY Allocation and Pipe Pitfalls

## Executive Summary

**Risk: Remote scans hang indefinitely or produce no visible output.**

When running remote commands over SSH that require interactive input (e.g., `sudo` password prompts), piping the output through tools like `tee` or capturing it with `> file 2>&1` breaks the TTY interaction. The password prompt either never reaches the user, gets swallowed by the pipe, or appears but can't accept input. The scan appears frozen with no indication of what went wrong.

**Impact:** Hung scans that require manual process cleanup on the target. In automated/demo contexts, the operator sees no output and no progress, leading to cancelled scans or forced reboots. SSH ControlMaster multiplexing compounds the problem by making `-t` (TTY allocation) unreliable on shared connections.

**Fix:** Separate interactive authentication from piped output. Cache sudo credentials via a direct SSH connection first (`ssh -t host "sudo -v"`), then run the piped command which uses cached credentials without prompting. See [Safe Patterns](#safe-patterns) below.

---

## Overview

This toolkit runs scans on remote targets over SSH. Several scans (Lynis, ClamAV install) require `sudo` on the remote host. We also want to stream scan output to both the terminal (for operator visibility) and a log file (for the report). These two requirements — interactive sudo and output streaming — conflict when combined naively.

## The Problem

### Problem 1: Pipes Swallow TTY Interaction

`ssh -t` allocates a pseudo-terminal on the remote host so interactive prompts (like `sudo`'s password prompt) can reach the user. But piping the SSH output through `tee` or any other command breaks this:

```bash
# BROKEN — sudo prompt appears but password input doesn't work
ssh -t user@host "sudo lynis audit system" | tee output.txt
```

What happens:
1. SSH allocates a remote PTY and runs `sudo lynis ...`
2. `sudo` writes `[sudo] password for user:` to the PTY
3. SSH forwards the prompt to local stdout
4. The pipe redirects stdout to `tee`, which displays the prompt
5. User types their password
6. The password goes to the **local shell's stdin**, NOT back through SSH to the remote `sudo`
7. `sudo` never receives the password, times out or retries, scan hangs

### Problem 2: Output Capture Hides Progress

Wrapping commands in a block redirect sends everything to a file with nothing on screen:

```bash
# BROKEN — user sees nothing while scan runs (may take 10+ minutes)
{
    echo "Scan Header"
    ssh user@host "clamscan --recursive / 2>&1"
} > scan-results.txt 2>&1
```

The operator sees a blank terminal for the entire scan duration. They can't tell if the scan is running, stuck, or crashed. For long scans (ClamAV full-disk, Lynis full audit), this creates the impression that the tool has frozen.

### Problem 3: SSH ControlMaster Breaks TTY on Multiplexed Connections

This toolkit uses SSH ControlMaster to avoid re-entering passwords for every command:

```bash
ssh -o ControlMaster=auto -o ControlPath=/tmp/ssh-%r@%h -o ControlPersist=300 user@host
```

Subsequent commands reuse this connection. But TTY allocation (`-t`) on a **multiplexed** connection is unreliable:

```bash
# First connection (ControlMaster) — established without TTY
ssh -o ControlMaster=auto ... user@host "uname -s"

# Later command requesting TTY — may not get a real PTY
ssh -t -o ControlMaster=auto ... user@host "sudo -v"
# Password prompt may not work correctly
```

The ControlMaster connection was opened without a TTY. Requesting a TTY on a multiplexed channel through it can result in:
- Password prompt appearing but not accepting input
- Password appearing on screen as you type (no terminal echo suppression)
- Prompt never appearing at all

## When It Triggers

| Scenario | Symptom | Root Cause |
|----------|---------|------------|
| `ssh -t host "sudo cmd" \| tee file` | Hangs at password prompt | Pipe breaks stdin passthrough |
| `{ ssh host "cmd" } > file 2>&1` | No output on screen | Block redirect captures everything |
| `ssh -t -o ControlPath=... "sudo -v"` | Password rejected or prompt garbled | Multiplexed TTY unreliable |
| `ssh host "sudo cmd" 2>/dev/null` | No password prompt visible | stderr redirect hides prompt |
| `ssh -t host "sudo cmd" 2>/dev/null` | Prompt may or may not appear | Depends on whether sudo uses PTY or stderr |

## Why This Keeps Happening

1. **`tee` is the obvious solution.** When you want output in two places, `tee` is what everyone reaches for. The TTY interaction is non-obvious.
2. **It works without sudo.** Non-interactive commands (like `clamscan` which doesn't need sudo) work fine through `tee`. The bug only appears when interactive input is needed.
3. **It works locally.** `sudo cmd | tee file` works on the local machine because `sudo` reads from `/dev/tty` directly. Over SSH, there is no local `/dev/tty` for the remote `sudo` to read from.
4. **ControlMaster is invisible.** The SSH multiplexing happens behind the scenes. Developers test with fresh connections (no ControlMaster) where `-t` works, then it breaks in the toolkit where ControlMaster is active.
5. **Failures look like wrong passwords.** The user types the correct password, it gets rejected, they try again, rejected again. It looks like an authentication problem, not a TTY problem.

## Impact on This Toolkit

| Impact | Detail |
|--------|--------|
| Hung scans | Lynis scan hangs waiting for sudo password that can never arrive |
| Invisible progress | ClamAV full-disk scan (5-15 minutes) with no output — operator thinks it's frozen |
| Stuck processes on target | Remote `sudo` and scan processes remain running after operator kills local scan |
| Manual cleanup required | Operator must SSH to target and `kill` stuck processes |
| Repeated password prompts | ControlMaster TTY issues cause sudo to reject valid passwords |

### Real Examples

**Lynis hang (v2.7.0):** `ssh_cmd_sudo "sudo lynis audit system" | tee "$lynis_file"` hung indefinitely. The `sudo` password prompt appeared through `tee`, but the user's password input never reached the remote `sudo`. Required manually killing PIDs on the target.

**ClamAV invisible scan:** `{ ssh_cmd "clamscan --recursive /" } > "$malware_file" 2>&1` ran for 10+ minutes with zero terminal output. Operator had no way to tell the scan was progressing.

**ControlMaster password rejection:** `ssh_cmd_sudo "sudo -v"` (using multiplexed connection with `-t`) prompted for password but rejected it repeatedly, even though the same password worked for the initial SSH login.

## Safe Patterns

### Pattern 1: Pre-cache Sudo Credentials (Interactive + Piped)

When you need both `sudo` and `tee`, separate them into two steps:

```bash
# Step 1: Cache sudo credentials via DIRECT connection (bypass ControlMaster)
# TTY works here because there's no pipe and no multiplexing
ssh -t user@host "sudo -v"

# Step 2: Run the actual command through tee
# sudo uses cached credentials — no password prompt needed
ssh -t -o ControlPath=/tmp/ssh-socket user@host "sudo lynis audit system" | tee output.txt
```

Key points:
- Step 1 uses a **direct** `ssh -t` (no ControlMaster socket) for reliable TTY
- `sudo -v` validates and caches credentials (default: 15 minutes)
- Step 2 can safely pipe through `tee` because `sudo` won't prompt again

### Pattern 2: Header to File, Stream with Tee (Non-Interactive)

For commands that don't need sudo (or where sudo is already cached):

```bash
# Write metadata header to file
{
    echo "Scan Report"
    echo "Host: $TARGET_HOST"
    echo "Started: $timestamp"
    echo ""
} > "$output_file"

# Stream scan output to both terminal and file
ssh user@host "clamscan --recursive / 2>&1" | tee -a "$output_file"
```

The `-a` flag appends to the file that already has the header.

### Pattern 3: Direct SSH for All Sudo Operations

If you don't need to capture output through a pipe, just use a direct SSH connection:

```bash
# SAFE — no pipe, no ControlMaster, clean TTY
ssh -t user@host "sudo apt update && sudo apt install -y lynis"
```

This is fine for install commands where you want the user to see output and enter their password.

### Anti-Patterns (Unsafe)

```bash
# UNSAFE — pipe breaks sudo password input
ssh -t user@host "sudo cmd" | tee file

# UNSAFE — no output visible to operator
{ ssh user@host "long-running-scan" } > file 2>&1

# UNSAFE — ControlMaster may not support TTY properly
ssh -t -o ControlPath=/tmp/ssh-mux user@host "sudo -v"

# UNSAFE — hides password prompt
ssh_cmd_sudo "sudo -v" 2>/dev/null

# MISLEADING — || true hides the failure
ssh_cmd_sudo "sudo -v" 2>/dev/null || true
```

## Quick Reference: Safe vs Unsafe

| Unsafe | Safe Replacement |
|--------|-----------------|
| `ssh -t host "sudo cmd" \| tee file` | `ssh -t host "sudo -v"` then `ssh -t host "sudo cmd" \| tee file` |
| `{ ssh host "cmd" } > file 2>&1` | Write header to file, then `ssh host "cmd" \| tee -a file` |
| `ssh -t -o ControlPath=... "sudo -v"` | `ssh -t host "sudo -v"` (bypass ControlMaster) |
| `ssh_cmd_sudo "sudo -v" 2>/dev/null` | `ssh -t host "sudo -v"` (let prompt show) |

## Decision Tree

```
Need to run a remote command?
├── Does it need sudo?
│   ├── YES: Is output being piped (tee, redirect)?
│   │   ├── YES: Use Pattern 1 (pre-cache sudo, then pipe)
│   │   └── NO: Use Pattern 3 (direct ssh -t, no pipe)
│   └── NO: Is the command long-running?
│       ├── YES: Use Pattern 2 (header to file, stream with tee)
│       └── NO: Simple ssh_cmd is fine
```

## Sudo Credential Caching

`sudo -v` refreshes the user's cached credentials. The default timeout is **15 minutes** (configurable via `/etc/sudoers` `timestamp_timeout`). After caching:

- `sudo` commands within the timeout won't prompt for a password
- This works across SSH sessions to the same host (credentials are per-user, per-TTY on the target)
- If a scan takes longer than the timeout, `sudo` will prompt again mid-scan (and hang if piped)

For scans that may exceed 15 minutes, consider:
1. Setting `NOPASSWD` for specific commands in sudoers (reduces security)
2. Running the scan as root directly
3. Breaking the scan into shorter segments

## Cleanup After Hung Scans

If a scan hangs due to these issues, processes may remain on the target:

```bash
# Check for stuck processes on target
ssh user@host "ps aux | grep -E 'sudo|lynis|clamscan'"

# Kill stuck processes
ssh user@host "sudo kill <PID>"

# Nuclear option — kill all scan-related processes
ssh user@host "sudo pkill -f lynis; sudo pkill -f clamscan"
```

## References

- [OpenSSH ControlMaster documentation](https://man.openbsd.org/ssh_config#ControlMaster)
- [sudo timestamp behavior](https://www.sudo.ws/docs/man/sudoers.man/#SECURITY_NOTES)
- [SSH pseudo-terminal allocation (-t flag)](https://man.openbsd.org/ssh#-t)
- [BashFAQ/024: I set variables in a pipeline. Why do they disappear?](https://mywiki.wooledge.org/BashFAQ/024)
