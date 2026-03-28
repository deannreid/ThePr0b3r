# ================================================================
# Script: thePr0b3r.ps1
# Purpose: Runner / entry point for THE Pr0b3r framework
# ================================================================

[CmdletBinding()]
param(
    [switch]$ShowHelp,
    [switch]$ShowVersion,
    [switch]$NoOperator,
    [switch]$RunAll,
    [switch]$Silent,
    [ValidateSet("silent", "info", "debug")]
    [string]$logger,
    [ValidateSet("red", "blue")]
    [string]$Strategy
)

# ---- Config file persistence: load saved values for anything not explicitly passed ----
$_configFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "prober.config.json"
if (Test-Path $_configFile) {
    try {
        $_saved = Get-Content $_configFile -Raw | ConvertFrom-Json
        if (-not $PSBoundParameters.ContainsKey("Strategy") -and $_saved.Strategy) {
            $Strategy = $_saved.Strategy
        }
        if (-not $PSBoundParameters.ContainsKey("logger") -and $_saved.logger) {
            $logger = $_saved.logger
        }
    }
    catch {}
}

# Apply defaults for anything still unset
if (-not $Strategy) { $Strategy = "red" }
if (-not $logger) { $logger = "silent" }

# Silent switch overrides logger
if ($Silent) { $logger = "silent" }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


# ------------------------------------------------------------
# Create Runtime State
# ------------------------------------------------------------

if (-not (Get-Variable ProberState -Scope Global -ErrorAction SilentlyContinue)) {

    $_probHost = try { [System.Net.Dns]::GetHostName() } catch { if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { "unknown" } }
    $_probUser = try { [Environment]::UserName }         catch { if ($env:USERNAME) { $env:USERNAME }     elseif ($env:USER) { $env:USER }     else { "unknown" } }

    $global:ProberState = [pscustomobject]@{

        Config            = [pscustomobject]@{
            DEBUG           = $false
            ADVANCED_MODE   = $false
            LoggerMode      = $logger
            ConsoleLogLevel = "NONE"
            Strategy        = $Strategy
            NoOperator      = $NoOperator.IsPresent
            RunAll          = $RunAll.IsPresent
            Silent          = $Silent.IsPresent
        }

        Runtime           = [pscustomobject]@{
            ScriptRoot      = $null
            LogRoot         = $null
            RunLogDir       = $null
            LogFile         = $null
            TempDir         = $null
            ModulesRoot     = $null
            DeferredModules = @{}
        }

        Tests             = @()
        Findings          = @{}
        EnvProfile        = "Unknown"
        OperatorTelemetry = $null
        _LoadedTestIds    = @()
        ExecutionHistory  = @{}

        RunContext        = [pscustomobject]@{
            RunId     = [guid]::NewGuid()
            StartTime = Get-Date
            Host      = $_probHost
            User      = $_probUser
        }
    }
}

# ------------------------------------------------------------
# Resolve Script Root
# ------------------------------------------------------------
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$global:ProberState.Runtime.ScriptRoot = $scriptRoot

# ------------------------------------------------------------
# Early Logging Bootstrap
# ------------------------------------------------------------
switch ($logger) {
    "silent" {
        $global:ProberState.Config.ConsoleLogLevel = "NONE"
        $global:ProberState.Config.DEBUG = $false
    }

    "info" {
        $global:ProberState.Config.ConsoleLogLevel = "INFO"
        $global:ProberState.Config.DEBUG = $false
    }

    "debug" {
        $global:ProberState.Config.ConsoleLogLevel = "DEBUG"
        $global:ProberState.Config.DEBUG = $true
    }
}

try {

    $loggingModule = Join-Path (Join-Path $scriptRoot "Modules") "Logging.psm1"

    if (Test-Path $loggingModule) {
        Import-Module $loggingModule -Force -ErrorAction Stop | Out-Null
    }

}
catch {
    Write-Host "CRITICAL: Unable to load Logging module." -ForegroundColor Red
}


# ------------------------------------------------------------
# Bootstrap Runtime State
# ------------------------------------------------------------
function fncShowCliHelp {

    Write-Host ""
    Write-Host "THE Pr0b3r Framework" -ForegroundColor Cyan
    Write-Host "----------------------------------------"
    Write-Host ""

    Write-Host "Usage:"
    Write-Host "  .\thePr0b3r.ps1 [options]"
    Write-Host ""

    Write-Host "Options:"
    Write-Host "  -ShowHelp          Display this help menu"
    Write-Host "  -ShowVersion       Display version information"
    Write-Host "  -NoOperator        Suppress operator context and risk banner"
    Write-Host "  -RunAll            Run all OS-relevant tests non-interactively, export, exit"
    Write-Host "  -Silent            Suppress all console output (implies -logger silent)"
    Write-Host "  -logger MODE       Set logging level"
    Write-Host "  -Strategy MODE     Set operator strategy (default: red)"
    Write-Host ""

    Write-Host "Logger Modes:"
    Write-Host "  silent             No console output"
    Write-Host "  info               Standard output (default)"
    Write-Host "  debug              Verbose debug logging"
    Write-Host ""

    Write-Host "Strategy Modes:"
    Write-Host "  red  (default)     Offensive - show attack surface and exploitation tests"
    Write-Host "  blue               Defensive - show security control validation tests"
    Write-Host ""

    Write-Host "Examples:"
    Write-Host "  .\thePr0b3r.ps1"
    Write-Host "  .\thePr0b3r.ps1 -Strategy blue"
    Write-Host "  .\thePr0b3r.ps1 -Strategy red -logger debug"
    Write-Host "  .\thePr0b3r.ps1 -ShowVersion"
    Write-Host ""

}

if ($ShowHelp) {
    fncShowCliHelp
    return
}

if ($ShowVersion) {

    Write-Host ""
    Write-Host "THE Pr0b3r Framework"
    Write-Host "Version: 4.2.0"
    Write-Host ""
    return
}
# ------------------------------------------------------------
# Bootstrap Runtime State
# ------------------------------------------------------------
function fncBootstrapProberState {

    fncLog "DEBUG" "Entering fncBootstrapProberState"

    if (-not $global:ProberState) {
        throw "ProberState not initialised"
    }

    fncLog "DEBUG" "ProberState already initialised"
}

# ------------------------------------------------------------
# Module Loader
# ------------------------------------------------------------
function fncImportLocalModules {

    param([string]$ModulesRoot = "")

    fncLog "INFO" "Starting module import routine"

    if ([string]::IsNullOrWhiteSpace($ModulesRoot)) {
        $ModulesRoot = Join-Path $scriptRoot "Modules"
    }

    # Store path so modules can lazy-load on demand
    $global:ProberState.Runtime.ModulesRoot = $ModulesRoot

    fncLog "DEBUG" ("Module root resolved to: {0}" -f $ModulesRoot)

    if (-not (Test-Path $ModulesRoot)) {
        fncLog "ERROR" ("Modules folder missing: {0}" -f $ModulesRoot)
        throw "Modules folder not found: $ModulesRoot"
    }

    # Detect OS before loading (no module dependency required)
    $_isWindows = $true
    try {
        if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
            if ($IsLinux -or $IsMacOS) { $_isWindows = $false }
        }
    }
    catch {}

    $required = @(
        "Core.psm1",
        "Output.psm1",
        "Logging.psm1",
        "Findings.psm1",
        "Registry.psm1",
        "Export.psm1",
        "UI.Render.psm1",
        "UI.Operator.psm1",
        "UI.Framework.psm1",
        "UI.Browser.psm1",
        "UI.Findings.psm1",
        "Menu.psm1"
    )

    # Optional modules: Name + whether they require Windows
    $optional = @(
        [pscustomobject]@{ Name = "Integrations.CIS.psm1"; WindowsOnly = $false },
        [pscustomobject]@{ Name = "Integrations.NIST.psm1"; WindowsOnly = $false },
        [pscustomobject]@{ Name = "Integrations.KEV.psm1"; WindowsOnly = $false },
        [pscustomobject]@{ Name = "Integrations.EntraID.psm1"; WindowsOnly = $false },
        [pscustomobject]@{ Name = "Integrations.AD.psm1"; WindowsOnly = $true },
        [pscustomobject]@{ Name = "Integrations.AWS.psm1"; WindowsOnly = $false },
        [pscustomobject]@{ Name = "Integrations.Azure.psm1"; WindowsOnly = $false },
    )

    foreach ($m in $required) {

        $path = Join-Path $ModulesRoot $m

        if (-not (Test-Path $path)) {
            fncLog "ERROR" ("Required module missing: {0}" -f $path)
            throw "Missing required module file: $path"
        }

        Import-Module $path -Force -ErrorAction Stop | Out-Null
        fncLog "INFO" ("Loaded module: {0}" -f $m)
    }

    foreach ($entry in $optional) {

        $m = $entry.Name
        $path = Join-Path $ModulesRoot $m

        if (-not (Test-Path $path)) {
            fncLog "WARN" ("Optional module not present: {0}" -f $m)
            $global:ProberState.Runtime.DeferredModules[$m] = "not-found"
            continue
        }

        # Skip Windows-only modules when running on Linux / macOS
        if ($entry.WindowsOnly -and -not $_isWindows) {
            fncLog "INFO" ("Skipping Windows-only module on this OS: {0}" -f $m)
            $global:ProberState.Runtime.DeferredModules[$m] = "os-unavailable"
            continue
        }

        Import-Module $path -Force -ErrorAction Stop | Out-Null
        fncLog "INFO" ("Loaded optional module: {0}" -f $m)
    }
}

# ------------------------------------------------------------
# Main Wrapper
# ------------------------------------------------------------
function fncRunMenu {

    param(
        [switch]$ShowHelp,
        [switch]$ShowVersion
    )

    try {

        fncBootstrapProberState
        $runId = $global:ProberState.RunContext.RunId
        $runtime = $global:ProberState.Runtime
        
        $runtime.LogRoot = Join-Path $runtime.ScriptRoot "Logs"
        $runtime.RunLogDir = Join-Path $runtime.LogRoot $runId

        New-Item -ItemType Directory -Path $runtime.RunLogDir -Force | Out-Null

        $runtime.LogFile = Join-Path $runtime.RunLogDir "thePr0b3r.log"

        fncLog "DEBUG" "Script entry point reached"
        fncImportLocalModules
        
        fncLogBanner "THE Pr0b3r Execution"
        fncLog "INFO" "Runner initialisation starting"
        fncLog "DEBUG" ("RunId: {0}" -f $global:ProberState.RunContext.RunId)

        if (Get-Command fncCreateTempDir -ErrorAction SilentlyContinue) {
            try { $global:ProberState.TempDir = fncCreateTempDir } catch {}
        }

        if (Get-Command fncInitFindings -ErrorAction SilentlyContinue) {
            fncInitFindings
        }
        else {
            $global:ProberState.Findings = @{}
        }

        if (Get-Command fncGetEnvProfile -ErrorAction SilentlyContinue) {
            try { $global:ProberState.EnvProfile = fncGetEnvProfile } catch { $global:ProberState.EnvProfile = "Unknown" }
        }

        if (Get-Command fncRegisterTests -ErrorAction SilentlyContinue) {
            fncLog "INFO" "Registering tests"
            fncRegisterTests
            fncLog "INFO" "Test registration complete"
        }

        # ---- Persist config (strategy + logger) for future runs ----
        try {
            $global:ProberState.Config.Strategy | Out-Null  # guard
            $savedCfg = [pscustomobject]@{
                Strategy = [string]$global:ProberState.Config.Strategy
                logger   = [string]$global:ProberState.Config.LoggerMode
            }
            $savedCfg | ConvertTo-Json -Compress | Set-Content -Path $_configFile -Encoding UTF8 -Force
        }
        catch {}

        # ---- Module health check ----
        $deferred = @{}
        try { $deferred = $global:ProberState.Runtime.DeferredModules } catch {}
        if ($deferred.Keys.Count -gt 0 -and -not $global:ProberState.Config.Silent) {
            if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {
                foreach ($modName in $deferred.Keys) {
                    $reason = $deferred[$modName]
                    $tag = if ($reason -eq "os-unavailable") { "OS unavailable" } else { "not found" }
                    fncPrintMessage ("Optional module skipped: {0}  [{1}]" -f $modName, $tag) "warning"
                }
            }
        }

        # ---- Batch mode: -RunAll ----
        if ($RunAll) {

            fncLog "INFO" "-RunAll: executing all OS-relevant tests"

            $currentOS = "Windows"
            try { if (Get-Command fncGetCurrentOS -ErrorAction SilentlyContinue) { $currentOS = fncGetCurrentOS } } catch {}

            $batchTests = @(
                $global:ProberState.Tests |
                Where-Object {
                    $_ -and
                    $_.Enabled -eq $true -and
                    (
                        (fncSafeString $_.OS) -eq "Any" -or
                        (fncSafeString $_.OS) -eq $currentOS
                    )
                }
            )

            $total = $batchTests.Count
            fncLog "INFO" ("-RunAll: {0} tests queued" -f $total)

            $i = 0
            foreach ($t in $batchTests) {
                $i++
                if (-not $global:ProberState.Config.Silent) {
                    if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {
                        fncPrintMessage ("[{0}/{1}] {2}" -f $i, $total, (fncSafeString $t.Name)) "info"
                    }
                }
                try {
                    if (Get-Command fncInvokeTestById -ErrorAction SilentlyContinue) {
                        fncInvokeTestById -TestId (fncSafeString $t.Id)
                    }
                }
                catch { fncLog "ERROR" ("Test failed: {0} - {1}" -f $t.Id, $_.Exception.Message) }
            }

            # Export all formats
            if (Get-Command fncExportFindingsToCsv  -ErrorAction SilentlyContinue) { try { fncExportFindingsToCsv } catch {} }
            if (Get-Command fncExportFindingsToJson -ErrorAction SilentlyContinue) { try { fncExportFindingsToJson } catch {} }
            if (Get-Command fncExportFindingsToHtml -ErrorAction SilentlyContinue) { try { fncExportFindingsToHtml } catch {} }

            if (Get-Command fncSaveExecutionHistory -ErrorAction SilentlyContinue) { try { fncSaveExecutionHistory } catch {} }

            fncLog "INFO" "-RunAll complete"
            return
        }

        if (-not (Get-Command fncMain -ErrorAction SilentlyContinue)) {
            fncLog "ERROR" "fncMain entry point not found"
            throw "fncMain not found. Ensure Menu.psm1 exports fncMain."
        }

        fncLog "INFO" "Launching main framework execution"
        fncMain
        fncLog "INFO" "Main framework execution completed"
    }
    catch {

        if (Get-Command fncLogException -ErrorAction SilentlyContinue) {
            fncLogException $_.Exception "Runner"
        }

        if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {

            fncPrintMessage ("Runner error: {0}" -f $_.Exception.Message) "error"
            fncPrintMessage ("Exception: {0}" -f $_.Exception.ToString()) "debug"
        }
        else {

            Write-Host ("Runner error: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-Host $_.Exception.ToString()
        }

        exit 1
    }
}

fncRunMenu -ShowHelp:$ShowHelp -ShowVersion:$ShowVersion