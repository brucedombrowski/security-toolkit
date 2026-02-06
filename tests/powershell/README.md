# PowerShell Tests

This directory contains Pester tests for the PowerShell components of the Security Toolkit.

## Prerequisites

- PowerShell 5.1+ (built into Windows 10/11)
- Pester 5.0+ (testing framework)

### Installing Pester

Pester is pre-installed on Windows 10+, but you may need to upgrade to version 5.0+:

```powershell
# Check current version
Get-Module -ListAvailable Pester

# Install/upgrade (run as Administrator or use -Scope CurrentUser)
Install-Module Pester -Force -Scope CurrentUser
```

## Running Tests

### Run All Tests

```powershell
./Invoke-AllTests.ps1
```

### Run with Detailed Output

```powershell
./Invoke-AllTests.ps1 -OutputFormat Detailed
```

### Run in CI Mode

```powershell
./Invoke-AllTests.ps1 -CI
```

### Run Specific Test File

```powershell
Invoke-Pester -Path ./Check-PII.Tests.ps1 -Output Detailed
```

### Run Tests by Tag

```powershell
# Run only integration tests
./Invoke-AllTests.ps1 -Tags 'Integration'

# Exclude known limitations
./Invoke-AllTests.ps1 -ExcludeTags 'Known'
```

## Test Structure

Tests follow Pester 5.x conventions:

```
tests/powershell/
+-- Invoke-AllTests.ps1            # Test runner (like run-all-tests.sh)
+-- Init-Lib.Tests.ps1             # init.ps1 library tests
+-- Check-PersonalInfo.Tests.ps1   # PII pattern tests
+-- Check-Secrets.Tests.ps1        # Secrets pattern tests
+-- fixtures/                      # Test data files
    +-- (generated during tests)
```

### Naming Convention

- Test files: `<ScriptName>.Tests.ps1`
- Must match the script being tested (e.g., `Check-PII.ps1` -> `Check-PII.Tests.ps1`)

### Test File Template

```powershell
#Requires -Version 5.1

BeforeAll {
    $script:TestDir = $PSScriptRoot
    $script:RepoDir = Split-Path -Parent (Split-Path -Parent $TestDir)

    # Import function being tested (when it exists)
    # . "$script:RepoDir/scripts/YourScript.ps1"
}

Describe 'Feature Name' {
    Context 'when condition is met' {
        It 'should do expected behavior' {
            $result = 'test'
            $result | Should -Be 'test'
        }
    }
}
```

## Pester Quick Reference

### Assertions (Should)

```powershell
$value | Should -Be 'expected'           # Exact equality
$value | Should -BeExactly 'Expected'    # Case-sensitive equality
$value | Should -Match 'pattern'         # Regex match
$value | Should -Not -Match 'pattern'    # Regex non-match
$value | Should -BeTrue                  # Boolean true
$value | Should -BeFalse                 # Boolean false
$value | Should -BeNullOrEmpty           # Null or empty
$value | Should -Exist                   # File/path exists
{ code } | Should -Throw                 # Throws exception
```

### Tags

```powershell
Describe 'Feature' -Tag 'Integration' {
    It 'test' -Tag 'Slow' { }
}
```

### Skip Tests

```powershell
It 'known limitation' -Skip {
    # This test is skipped
}
```

## Mapping to Bash Tests

| Bash Test | PowerShell Test | Status |
|-----------|-----------------|--------|
| (init.sh) | Init-Lib.Tests.ps1 | Complete |
| test-pii-patterns.sh | Check-PersonalInfo.Tests.ps1 | Complete |
| test-secrets-patterns.sh | Check-Secrets.Tests.ps1 | Complete |
| test-mac-patterns.sh | Check-MAC.Tests.ps1 | Planned |
| test-audit-logging.sh | Audit-Log.Tests.ps1 | Planned |

## CI Integration

The tests can be integrated into GitHub Actions:

```yaml
- name: Run PowerShell Tests
  shell: pwsh
  run: |
    ./tests/powershell/Invoke-AllTests.ps1 -CI
```

## References

- [Pester Documentation](https://pester.dev/docs/quick-start)
- [PowerShell Testing Guidelines](https://github.com/PowerShell/PowerShell/blob/master/docs/testing-guidelines/testing-guidelines.md)
