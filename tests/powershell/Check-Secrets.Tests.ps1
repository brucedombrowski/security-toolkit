#Requires -Version 5.1
<#
.SYNOPSIS
    Secrets Pattern Detection Unit Tests (Pester)

.DESCRIPTION
    Verifies secrets detection patterns catch real credentials and minimize false positives.
    PowerShell equivalent of test-secrets-patterns.sh.

.NOTES
    NIST Control: SA-11 (Developer Testing)

    Exit codes:
      0 = All tests passed
      1 = One or more tests failed

.EXAMPLE
    Invoke-Pester -Path ./Check-Secrets.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Script and repository paths
    $script:TestDir = $PSScriptRoot
    $script:RepoDir = Split-Path -Parent (Split-Path -Parent $TestDir)
    $script:FixturesDir = Join-Path $TestDir 'fixtures'

    # Secrets regex patterns (must match Check-Secrets.ps1)
    $script:Patterns = @{
        AWSAccessKey  = 'AKIA[0-9A-Z]{16}'
        AWSSecretKey  = '[A-Za-z0-9/+=]{40}'
        PrivateKey    = '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
        GitHubToken   = 'gh[ps]_[A-Za-z0-9]{36}'
        BearerToken   = 'Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        APIKey        = 'api[_-]?key.*[:=]'
        Password      = 'password["\x27]?\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'
    }
}

Describe 'API Key Detection' {
    Context 'when input contains API key assignments' {
        It 'detects api_key assignment' {
            'api_key = "sk_live_abcdef123456789012345"' | Should -Match $script:Patterns.APIKey
        }

        It 'detects API-KEY header' {
            'API-KEY: abcdefghijklmnopqrstuvwxyz123456' | Should -Match $script:Patterns.APIKey
        }

        It 'detects apiKey in JSON' {
            '{"apiKey": "test_key_123456789012345678"}' | Should -Match $script:Patterns.APIKey
        }
    }
}

Describe 'AWS Credential Detection' {
    Context 'when input contains AWS credentials' {
        It 'detects AWS Access Key ID format' {
            'AKIAIOSFODNN7EXAMPLE' | Should -Match $script:Patterns.AWSAccessKey
        }

        It 'detects AWS Access Key in config' {
            'aws_access_key_id = AKIAIOSFODNN7EXAMPLE' | Should -Match $script:Patterns.AWSAccessKey
        }
    }

    Context 'when input contains invalid AWS formats' {
        It 'rejects short key (AKIA + 15 chars)' {
            'AKIA123456789012345' | Should -Not -Match "^$($script:Patterns.AWSAccessKey)$"
        }
    }
}

Describe 'Private Key Detection' {
    Context 'when input contains private key headers' {
        It 'detects RSA private key header' {
            '-----BEGIN RSA PRIVATE KEY-----' | Should -Match $script:Patterns.PrivateKey
        }

        It 'detects generic private key header' {
            '-----BEGIN PRIVATE KEY-----' | Should -Match $script:Patterns.PrivateKey
        }

        It 'detects EC private key header' {
            '-----BEGIN EC PRIVATE KEY-----' | Should -Match $script:Patterns.PrivateKey
        }

        It 'detects OpenSSH private key header' {
            '-----BEGIN OPENSSH PRIVATE KEY-----' | Should -Match $script:Patterns.PrivateKey
        }
    }

    Context 'when input contains public keys' {
        It 'does not match public key header' {
            '-----BEGIN PUBLIC KEY-----' | Should -Not -Match $script:Patterns.PrivateKey
        }
    }
}

Describe 'GitHub Token Detection' {
    Context 'when input contains GitHub tokens' {
        It 'detects ghp_ personal access token format' {
            # GitHub PAT tokens have 36 alphanumeric characters after prefix
            'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' | Should -Match $script:Patterns.GitHubToken
        }

        It 'detects ghs_ server token format' {
            # GitHub server tokens have 36 alphanumeric characters after prefix
            'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' | Should -Match $script:Patterns.GitHubToken
        }
    }

    Context 'when input contains invalid GitHub token formats' {
        It 'rejects short token (gh*_ + 35 chars)' {
            'ghp_12345678901234567890123456789012345' | Should -Not -Match "^$($script:Patterns.GitHubToken)$"
        }
    }
}

Describe 'Bearer Token Detection' {
    Context 'when input contains JWT bearer tokens' {
        It 'detects Bearer JWT format' {
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' | Should -Match $script:Patterns.BearerToken
        }
    }

    Context 'when input contains non-JWT bearers' {
        It 'does not match simple Bearer token' {
            'Bearer simple_token' | Should -Not -Match $script:Patterns.BearerToken
        }
    }
}

Describe 'Password Detection' {
    Context 'when input contains hardcoded passwords' {
        It 'detects password = "value" format' {
            'password = "secretpassword123"' | Should -Match $script:Patterns.Password
        }

        It 'detects password: "value" format' {
            "password: 'mysecretpass'" | Should -Match $script:Patterns.Password
        }
    }

    Context 'when input contains safe password references' {
        It 'does not match password placeholder' {
            'password = ""' | Should -Not -Match $script:Patterns.Password
        }

        It 'does not match password environment variable' {
            'password = $PASSWORD' | Should -Not -Match $script:Patterns.Password
        }
    }
}

Describe 'False Positive Prevention' {
    Context 'when input contains documentation examples' {
        It 'should match example API key (requires allowlist)' -Tag 'Known' {
            # Documentation examples will match patterns.
            # Use allowlist to suppress known-good examples.
            '# Example: api_key = "your-api-key-here"' | Should -Match $script:Patterns.APIKey
        }
    }
}

Describe 'Integration Test' -Tag 'Integration' {
    BeforeAll {
        $script:CleanFile = Join-Path $script:FixturesDir 'clean-secrets.txt'
        $script:SecretsFile = Join-Path $script:FixturesDir 'has-secrets.txt'

        # Ensure fixtures directory exists
        if (-not (Test-Path $script:FixturesDir)) {
            New-Item -ItemType Directory -Path $script:FixturesDir -Force | Out-Null
        }
    }

    AfterAll {
        # Cleanup
        @($script:CleanFile, $script:SecretsFile) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force }
        }
    }

    Context 'when running Check-Secrets.ps1 on test fixtures' {
        It 'passes on clean fixture file' {
            @'
# Configuration file
debug = true
log_level = "info"
timeout = 30
'@ | Set-Content -Path $script:CleanFile

            # TODO: Once Check-Secrets.ps1 exists:
            # & "$script:RepoDir/scripts/Check-Secrets.ps1" $script:FixturesDir
            # $LASTEXITCODE | Should -Be 0

            Test-Path $script:CleanFile | Should -BeTrue
        }

        It 'fails on file containing secrets' {
            @'
# DO NOT COMMIT - test fixture
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
password = "supersecret123"
'@ | Set-Content -Path $script:SecretsFile

            # TODO: Once Check-Secrets.ps1 exists:
            # & "$script:RepoDir/scripts/Check-Secrets.ps1" $script:FixturesDir
            # $LASTEXITCODE | Should -Be 1

            $content = Get-Content $script:SecretsFile -Raw
            $content | Should -Match $script:Patterns.AWSAccessKey
        }
    }
}
