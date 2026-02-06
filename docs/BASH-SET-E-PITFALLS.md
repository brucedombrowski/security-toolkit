# Bash `set -e` and Arithmetic Pitfalls

## Executive Summary

**Risk: Silent scan failure creating false assurance of security.**

Bash's `set -e` (exit on error) interacts with arithmetic operations in a way that silently kills scripts when counter variables are zero. The expression `((count++))` returns exit code 1 when `count=0`, causing `set -e` to terminate the script with no error message. Security scans appear to complete cleanly with zero findings when they actually crashed mid-run.

**Impact:** Incomplete scans that look like clean scans. This is a **false assurance vulnerability** — stakeholders believe a system passed verification when it was never fully scanned. In federal compliance contexts (NIST 800-53, 800-171), this undermines the integrity of security attestations.

**Fix:** Replace all `((count++))` with `count=$((count + 1))`. Variable assignment always returns exit code 0, eliminating the interaction. See [Safe Patterns](#safe-patterns) below.

---

## Overview

Every script in this toolkit uses `set -e` (exit on error). This document explains a recurring class of bugs caused by the interaction between `set -e` and Bash arithmetic operations, and how to avoid them.

## The Problem

`set -e` tells Bash: exit immediately if any command returns a non-zero exit code.

Bash arithmetic `((...))` returns the **arithmetic result as an exit code**: zero = failure (exit 1), non-zero = success (exit 0). This is the opposite of what most developers expect.

```bash
set -e
count=0
((count++))   # Script silently dies here
echo "This never runs"
```

`((count++))` is post-increment. It returns the **old value** (0) before incrementing. Bash interprets 0 as false, returns exit code 1, and `set -e` kills the script. No error message. No stack trace.

## When It Triggers

| Expression | Value Before | Returns | Exit Code | `set -e` Result |
|------------|-------------|---------|-----------|-----------------|
| `((count++))` | 0 | 0 (old) | 1 (false) | **SCRIPT DIES** |
| `((count++))` | 1 | 1 (old) | 0 (true) | OK |
| `((count++))` | 5 | 5 (old) | 0 (true) | OK |
| `((++count))` | 0 | 1 (new) | 0 (true) | OK |
| `((count--))` | 1 | 1 (old) | 0 (true) | OK |
| `((count--))` | 0 | 0 (old) | 1 (false) | **SCRIPT DIES** |
| `((count = 0))` | any | 0 | 1 (false) | **SCRIPT DIES** |

Key insight: it **only** fails when the expression evaluates to exactly 0. This means:
- It works in testing (if your test starts at 1)
- It works on the second iteration
- It works most of the time
- Then it silently kills the script on the one case that matters

## Why This Keeps Happening

1. **Counters start at 0.** Every `pass_count=0`, `fail_count=0`, `file_count=0` is a loaded gun.
2. **`((count++))` is idiomatic.** It's the "obvious" way to increment in Bash. Every developer writes it instinctively.
3. **Failures are silent.** No error message, no indication of what went wrong. The script just stops. Downstream code may see empty results and assume a clean scan.
4. **Bash 3.2 compounds the issue.** Stock macOS ships Bash 3.2 (from 2007, due to Apple's GPLv3 licensing policy). Some workarounds available in Bash 4+ don't exist, and C-style `for ((i=0; ...))` loops have the same zero-value trap.

## Impact on This Toolkit

| Impact | Detail |
|--------|--------|
| Scan accuracy | Counter resets mean scan results report 0 findings when there were findings |
| Silent failures | Looks like a clean scan when it actually crashed mid-run |
| macOS default | Bash 3.2 is on every Mac — our primary user platform |
| Federal compliance | A scan that silently produces empty results creates false assurance of security |

### Real Example: Issue #131

`check-pii.sh` and `check-secrets.sh` used pipe-fed `while` loops with counters. Variables set inside the loop were lost (subshell), and counter increments on zero values silently killed scan logic. Scans appeared to pass with zero findings when there were actual findings.

## Safe Patterns

### Incrementing

```bash
# UNSAFE — dies when count=0
((count++))

# SAFE — assignment always returns exit 0
count=$((count + 1))
```

`count=$((count + 1))` is the **required pattern** in this toolkit because:
- Variable assignment always returns exit code 0
- Works on Bash 3.2+
- No workaround hacks needed
- Clear intent

### Other Workarounds (Not Recommended)

```bash
# Works but obscures intent
((count++)) || true

# Pre-increment avoids the zero problem but not other arithmetic zeros
((++count))
```

These work but `|| true` masks real errors, and `((++count))` only solves the increment case, not the general arithmetic case.

### Arithmetic Comparisons

```bash
# UNSAFE — if result is 0, set -e kills the script
((remaining = total - processed))

# SAFE
remaining=$((total - processed))
```

### C-Style For Loops

```bash
# UNSAFE on Bash 3.2 — may not be supported or may trigger set -e
for ((i = 0; i < count; i++)); do

# SAFE — POSIX compatible
i=0
while [ "$i" -lt "$count" ]; do
    # ... body ...
    i=$((i + 1))
done
```

### Conditional Arithmetic

```bash
# UNSAFE — ((0)) returns exit 1
if ((count == 0)); then

# SAFE
if [ "$count" -eq 0 ]; then
```

## Quick Reference: Safe vs Unsafe

| Unsafe | Safe Replacement |
|--------|-----------------|
| `((count++))` | `count=$((count + 1))` |
| `((count--))` | `count=$((count - 1))` |
| `((count += n))` | `count=$((count + n))` |
| `((result = a - b))` | `result=$((a - b))` |
| `for ((i=0; ...))` | `while [ "$i" -lt ... ]` |
| `if ((count == 0))` | `if [ "$count" -eq 0 ]` |

## Bash 3.2 Compatibility Note

macOS ships Bash 3.2 due to Apple's refusal to adopt GPLv3-licensed software. This toolkit targets Bash 3.2+ for maximum macOS compatibility. Features unavailable in 3.2:

| Feature | Bash Version | Alternative |
|---------|-------------|-------------|
| `declare -n` (namerefs) | 4.3+ | Pass variable names and use `eval` carefully or restructure |
| Associative arrays `declare -A` | 4.0+ | Use `case` statements or flat variables |
| `${var,,}` (lowercase) | 4.0+ | `echo "$var" \| tr '[:upper:]' '[:lower:]'` |
| `${var^^}` (uppercase) | 4.0+ | `echo "$var" \| tr '[:lower:]' '[:upper:]'` |
| `readarray` / `mapfile` | 4.0+ | `while IFS= read -r` loops |
| `|&` (pipe stderr) | 4.0+ | `2>&1 \|` |

## Related Issues

- [#131](https://github.com/brucedombrowski/security-toolkit/issues/131) — Pipe subshell variable loss in check-pii.sh and check-secrets.sh
- [#132](https://github.com/brucedombrowski/security-toolkit/issues/132) — Bash 3.2 compatibility sweep across multiple scripts

## References

- [BashFAQ/105: Why doesn't set -e work as expected?](https://mywiki.wooledge.org/BashFAQ/105)
- [Bash Pitfalls](https://mywiki.wooledge.org/BashPitfalls)
- [POSIX Shell Command Language](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)
