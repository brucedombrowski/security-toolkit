#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for scripts/lib/init.ps1

.DESCRIPTION
    Tests the PowerShell initialization library for the Security Toolkit.

.NOTES
    Run with: Invoke-Pester -Path ./tests/powershell/Init-Lib.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:TestDir = $PSScriptRoot
    $script:RepoDir = Split-Path -Parent (Split-Path -Parent $TestDir)
    $script:InitPath = Join-Path $RepoDir 'scripts/lib/init.ps1'
}

Describe 'init.ps1 file structure' {
    It 'exists at expected path' {
        Test-Path $script:InitPath | Should -BeTrue
    }

    It 'contains required functions' {
        $content = Get-Content $script:InitPath -Raw
        $content | Should -Match 'function Initialize-SecurityToolkit'
        $content | Should -Match 'function Get-TargetDirectory'
        $content | Should -Match 'function Write-ScriptHeader'
        $content | Should -Match 'function Write-LibraryStatus'
    }

    It 'has PowerShell 5.1 requirement' {
        $content = Get-Content $script:InitPath -Raw
        $content | Should -Match '#Requires -Version 5.1'
    }

    It 'prevents direct execution' {
        $content = Get-Content $script:InitPath -Raw
        $content | Should -Match 'InvocationName -ne'
    }
}

Describe 'Initialize-SecurityToolkit' {
    BeforeAll {
        # Dot-source the init script
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
    }

    Context 'when in a git repository' {
        BeforeAll {
            Initialize-SecurityToolkit
        }

        It 'sets TOOLKIT_VERSION' {
            $script:TOOLKIT_VERSION | Should -Not -BeNullOrEmpty
        }

        It 'sets TOOLKIT_COMMIT' {
            $script:TOOLKIT_COMMIT | Should -Not -BeNullOrEmpty
        }

        It 'sets TIMESTAMP in ISO 8601 format' {
            $script:TIMESTAMP | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }

        It 'sets LIB_DIR to lib directory' {
            $script:LIB_DIR | Should -Match 'scripts[\\/]lib$'
        }

        It 'sets SECURITY_REPO_DIR to repository root' {
            Test-Path (Join-Path $script:SECURITY_REPO_DIR 'CLAUDE.md') | Should -BeTrue
        }
    }

    Context 'library availability flags' {
        It 'sets AUDIT_AVAILABLE flag' {
            $script:AUDIT_AVAILABLE | Should -BeIn @($true, $false)
        }

        It 'sets TIMESTAMPS_AVAILABLE flag' {
            $script:TIMESTAMPS_AVAILABLE | Should -BeIn @($true, $false)
        }

        It 'sets PROGRESS_AVAILABLE flag' {
            $script:PROGRESS_AVAILABLE | Should -BeIn @($true, $false)
        }

        It 'sets TOOLKIT_AVAILABLE flag' {
            $script:TOOLKIT_AVAILABLE | Should -BeIn @($true, $false)
        }
    }
}

Describe 'Get-TargetDirectory' {
    BeforeAll {
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
        Initialize-SecurityToolkit
    }

    It 'returns first non-flag argument' {
        $result = Get-TargetDirectory @('/path/to/target', '-verbose')
        $result | Should -Be '/path/to/target'
    }

    It 'skips -flag arguments' {
        $result = Get-TargetDirectory @('-n', '-verbose', '/path/to/target')
        $result | Should -Be '/path/to/target'
    }

    It 'returns SECURITY_REPO_DIR when no args' {
        $result = Get-TargetDirectory @()
        $result | Should -Be $script:SECURITY_REPO_DIR
    }

    It 'returns SECURITY_REPO_DIR when only flags' {
        $result = Get-TargetDirectory @('-n', '-verbose')
        $result | Should -Be $script:SECURITY_REPO_DIR
    }
}

Describe 'Write-ScriptHeader' {
    BeforeAll {
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
        Initialize-SecurityToolkit
    }

    It 'outputs formatted header without error' {
        { Write-ScriptHeader -Name 'Test Script' -Target $script:SECURITY_REPO_DIR } | Should -Not -Throw
    }

    It 'uses default target when not specified' {
        { Write-ScriptHeader -Name 'Test Script' } | Should -Not -Throw
    }
}

Describe 'Write-LibraryStatus' {
    BeforeAll {
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
    }

    It 'outputs library status without error' {
        { Write-LibraryStatus } | Should -Not -Throw
    }
}

Describe 'Color output helpers' {
    BeforeAll {
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
    }

    It 'Write-Pass works' {
        { Write-Pass 'Test message' } | Should -Not -Throw
    }

    It 'Write-Fail works' {
        { Write-Fail 'Test message' } | Should -Not -Throw
    }

    It 'Write-WarningMessage works' {
        { Write-WarningMessage 'Test message' } | Should -Not -Throw
    }

    It 'Write-Info works' {
        { Write-Info 'Test message' } | Should -Not -Throw
    }
}

Describe 'Test-CIEnvironment' {
    BeforeAll {
        $script:SCRIPT_DIR = Join-Path $script:RepoDir 'scripts'
        . $script:InitPath
    }

    It 'returns boolean' {
        $result = Test-CIEnvironment
        $result | Should -BeIn @($true, $false)
    }

    It 'detects GitHub Actions' -Tag 'Integration' {
        # This test will pass differently in CI vs local
        if ($env:GITHUB_ACTIONS) {
            Test-CIEnvironment | Should -BeTrue
        } else {
            # Just verify it doesn't throw
            { Test-CIEnvironment } | Should -Not -Throw
        }
    }
}
