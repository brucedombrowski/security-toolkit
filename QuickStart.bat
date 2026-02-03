@echo off
REM ============================================================================
REM Security Toolkit QuickStart (Windows)
REM
REM Purpose: Easy entry point for new users to demo the security toolkit
REM Usage: Double-click QuickStart.bat or run from Command Prompt
REM ============================================================================

setlocal EnableDelayedExpansion

REM Colors via escape codes (Windows 10+)
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
    set "ESC=%%b"
)

REM ============================================================================
REM Banner
REM ============================================================================

echo.
echo %ESC%[36m========================================================================%ESC%[0m
echo %ESC%[36m           Security Toolkit - QuickStart Demo (Windows)                 %ESC%[0m
echo %ESC%[36m========================================================================%ESC%[0m
echo.
echo   Scan your projects for:
echo     * PII (Social Security Numbers, Phone Numbers, etc.)
echo     * Secrets (API Keys, Passwords, Tokens)
echo     * Security configuration issues
echo.
echo %ESC%[36m========================================================================%ESC%[0m
echo.

REM ============================================================================
REM Check for PowerShell
REM ============================================================================

echo [*] Checking for PowerShell...
where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PWSH=pwsh"
    echo [+] PowerShell 7+ found
    goto :CheckScripts
)

where powershell >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PWSH=powershell"
    echo [+] Windows PowerShell found
    goto :CheckScripts
)

echo [!] PowerShell not found. Please install PowerShell.
echo     https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell
pause
exit /b 1

REM ============================================================================
REM Check for Scripts
REM ============================================================================

:CheckScripts
echo [*] Checking for toolkit scripts...

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPTS=%SCRIPT_DIR%scripts\lib"

if exist "%PS_SCRIPTS%\init.ps1" (
    echo [+] PowerShell library found
) else (
    echo [!] PowerShell library not found at %PS_SCRIPTS%
    echo     Please ensure you're running from the toolkit root directory.
    pause
    exit /b 1
)

echo.

REM ============================================================================
REM Target Selection
REM ============================================================================

:SelectTarget
echo What would you like to scan?
echo.
echo   1) Current directory - %CD%
echo   2) Custom path       - Enter a specific folder
echo   3) Exit
echo.
set /p "CHOICE=Select option [1-3]: "

if "%CHOICE%"=="1" (
    set "TARGET_DIR=%CD%"
    goto :SelectScan
)
if "%CHOICE%"=="2" (
    set /p "TARGET_DIR=Enter full path: "
    goto :SelectScan
)
if "%CHOICE%"=="3" (
    exit /b 0
)

echo [!] Invalid selection
goto :SelectTarget

REM ============================================================================
REM Scan Selection
REM ============================================================================

:SelectScan
echo.
echo Which scans would you like to run?
echo.
echo   1) Quick scan  - PII + Secrets (using PowerShell)
echo   2) Full scan   - Run all available scans
echo   3) Test only   - Run PowerShell test suite
echo.
set /p "SCAN_CHOICE=Select option [1-3]: "

if "%SCAN_CHOICE%"=="1" goto :QuickScan
if "%SCAN_CHOICE%"=="2" goto :FullScan
if "%SCAN_CHOICE%"=="3" goto :RunTests

echo [!] Invalid selection
goto :SelectScan

REM ============================================================================
REM Quick Scan
REM ============================================================================

:QuickScan
echo.
echo [*] Running quick scan on: %TARGET_DIR%
echo.

REM Check for Check-PersonalInfo.ps1
if exist "%SCRIPT_DIR%scripts\Check-PersonalInfo.ps1" (
    echo [*] Running PII scan...
    %PWSH% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\Check-PersonalInfo.ps1" -Target "%TARGET_DIR%"
) else (
    echo [!] Check-PersonalInfo.ps1 not found - PII scan skipped
    echo     This script is under development. See Issue #12.
)

echo.

REM Check for Check-Secrets.ps1
if exist "%SCRIPT_DIR%scripts\Check-Secrets.ps1" (
    echo [*] Running secrets scan...
    %PWSH% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\Check-Secrets.ps1" -Target "%TARGET_DIR%"
) else (
    echo [!] Check-Secrets.ps1 not found - Secrets scan skipped
    echo     This script is under development. See Issue #13.
)

goto :Summary

REM ============================================================================
REM Full Scan
REM ============================================================================

:FullScan
echo.
echo [*] Running full scan on: %TARGET_DIR%
echo.
echo     Note: Full Windows scan support is under development.
echo     For complete scanning, consider using WSL with the Bash scripts.
echo.

goto :QuickScan

REM ============================================================================
REM Run Tests
REM ============================================================================

:RunTests
echo.
echo [*] Running PowerShell test suite...
echo.

if exist "%SCRIPT_DIR%tests\powershell\Invoke-AllTests.ps1" (
    %PWSH% -ExecutionPolicy Bypass -File "%SCRIPT_DIR%tests\powershell\Invoke-AllTests.ps1"
) else (
    echo [!] Test runner not found
)

goto :End

REM ============================================================================
REM Summary
REM ============================================================================

:Summary
echo.
echo %ESC%[36m========================================================================%ESC%[0m
echo                              Scan Complete
echo %ESC%[36m========================================================================%ESC%[0m
echo.
echo   Target: %TARGET_DIR%
echo.
echo   For detailed results, check the output above.
echo.
echo   To run Bash scans (more complete), use WSL:
echo     wsl ./scripts/run-all-scans.sh "%TARGET_DIR%"
echo.
echo %ESC%[36m========================================================================%ESC%[0m

:End
echo.
pause
exit /b 0
