# ================================================================
# Module  : Core.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Ensure ProberState Exists
# ------------------------------------------------------------
if (-not (Get-Variable ProberState -Scope Global -ErrorAction SilentlyContinue)) {

    fncLog "DEBUG" "Core bootstrap creating minimal ProberState"

    $_probHost = try { [System.Net.Dns]::GetHostName() } catch { if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { "unknown" } }
    $_probUser = try { [Environment]::UserName }         catch { if ($env:USERNAME) { $env:USERNAME }     elseif ($env:USER) { $env:USER }     else { "unknown" } }

    $global:ProberState = [pscustomobject]@{
        Config            = [pscustomobject]@{
            DEBUG         = $false
            ADVANCED_MODE = $false
        }

        Tests             = @()
        Findings          = @{}
        TempDir           = $null
        EnvProfile        = "Unknown"
        OperatorTelemetry = $null
        _LoadedTestIds    = @()


        RunContext        = [pscustomobject]@{
            RunId     = [guid]::NewGuid()
            StartTime = Get-Date
            Host      = $_probHost
            User      = $_probUser
        }
    }

    fncLog "INFO" "Core created minimal ProberState container"
}

# ------------------------------------------------------------
# Ensure Required Properties Exist
# ------------------------------------------------------------
$requiredProps = @(
    @{ Name = "Tests"; Value = @() },
    @{ Name = "Findings"; Value = @{} },
    @{ Name = "TempDir"; Value = $null },
    @{ Name = "EnvProfile"; Value = "Unknown" },
    @{ Name = "OperatorTelemetry"; Value = $null },
    @{ Name = "_LoadedTestIds"; Value = @() }

)

foreach ($p in $requiredProps) {
    if ($global:ProberState.PSObject.Properties.Name -notcontains $p.Name) {

        fncLog "DEBUG" ("Core adding missing ProberState property: {0}" -f $p.Name)

        $global:ProberState | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value
    }
}

# ------------------------------------------------------------
# Config alias
# ------------------------------------------------------------
if (-not (Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {

    $global:config = $global:ProberState.Config
    fncLog "DEBUG" "Core initialised global config alias"
}

# Cosmetic globals
if (-not (Get-Variable CurrentBlurb -Scope Global -ErrorAction SilentlyContinue)) {

    $global:CurrentBlurb = "Enumerating wisdom"
    fncLog "DEBUG" "Core initialised default blurb"
}

function fncGetScriptDirectory {

    fncLog "DEBUG" "fncGetScriptDirectory invoked"

    try {
        if ($PSScriptRoot) { return $PSScriptRoot }
        return (Split-Path -Parent $MyInvocation.MyCommand.Path)
    }
    catch {
        fncLogException $_.Exception "fncGetScriptDirectory"
        return (Get-Location).Path
    }
}

function fncGetCurrentOS {

    # PS7+ exposes automatic OS variables
    try {
        if (Get-Variable IsWindows -ErrorAction SilentlyContinue) {
            if ($IsWindows) { return "Windows" }
            if ($IsLinux) { return "Linux" }
            if ($IsMacOS) { return "macOS" }
        }
    }
    catch {}

    # RuntimeInformation available in .NET Core / PS7 even without the automatic vars
    try {
        $rid = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        if ($rid -like "*Windows*") { return "Windows" }
        if ($rid -like "*Linux*") { return "Linux" }
        if ($rid -like "*Darwin*" -or $rid -like "*macOS*") { return "macOS" }
    }
    catch {}

    # PS5.1 runs exclusively on Windows - safe fallback
    return "Windows"
}

function fncIsAdmin {

    fncLog "DEBUG" "Checking administrative privileges"

    try {
        $currentOS = fncGetCurrentOS

        if ($currentOS -ne "Windows") {
            # On Linux/macOS root has uid 0
            $uid = & id -u 2>$null
            return ($uid -eq "0")
        }

        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        fncLogException $_.Exception "fncIsAdmin"
        return $false
    }
}

function fncCreateTempDir {

    fncLog "DEBUG" "fncCreateTempDir invoked"

    try {
        if ($global:ProberState.TempDir -and (Test-Path $global:ProberState.TempDir)) {
            fncLog "DEBUG" ("Reusing existing temp directory: {0}" -f $global:ProberState.TempDir)
            return $global:ProberState.TempDir
        }
    }
    catch {
        fncLogException $_.Exception "fncCreateTempDir existing temp check"
    }

    if (
        -not $global:ProberState.PSObject.Properties.Name -contains "Runtime" -or
        -not $global:ProberState.Runtime.RunLogDir
    ) {
        throw "RunLogDir not initialised by runner."
    }

    $path = Join-Path $global:ProberState.Runtime.RunLogDir "Temp"

    try {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $global:ProberState.TempDir = $path

        fncLog "INFO" ("Created temp directory: {0}" -f $path)

        return $path
    }
    catch {
        fncLogException $_.Exception "fncCreateTempDir directory creation"
        return $null
    }
}

function fncCleanupTempDir {

    fncLog "DEBUG" "fncCleanupTempDir invoked"

    try {
        if ($global:ProberState.TempDir -and (Test-Path $global:ProberState.TempDir)) {

            fncLog "DEBUG" ("Removing temp directory: {0}" -f $global:ProberState.TempDir)

            Remove-Item $global:ProberState.TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        fncLogException $_.Exception "fncCleanupTempDir"
    }

    $global:ProberState.TempDir = $null
}

function fncGetEnvProfile {

    fncLog "DEBUG" "fncGetEnvProfile invoked"

    try {
        $currentOS = fncGetCurrentOS

        if ($currentOS -ne "Windows") {
            fncLog "DEBUG" ("Non-Windows platform ({0}), returning Workstation" -f $currentOS)
            return "Workstation"
        }

        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $osi = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

        $isServer = $false
        if ($osi -and $osi.Caption -match "(?i)\bserver\b") { $isServer = $true }

        $isDC = $false
        if ($cs -and $cs.DomainRole -ge 4) { $isDC = $true }

        if ($isDC) {
            fncLog "DEBUG" "Environment profile detected as Domain Controller"
            return "Domain"
        }

        if ($isServer) {
            fncLog "DEBUG" "Environment profile detected as Server"
            return "Server"
        }

        fncLog "DEBUG" "Environment profile detected as Workstation"
        return "Workstation"
    }
    catch {
        fncLogException $_.Exception "fncGetEnvProfile"
        return "Unknown"
    }
}

# ------------------------------------------------------------
# Function: fncAskYesNo
# ------------------------------------------------------------
function fncAskYesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [ValidateSet("Y", "N")][string]$Default = "N"
    )

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" ("Prompt issued: {0}" -f $Question) } } catch {}

    $defTxt = if ($Default -eq "Y") { "Y/n" } else { "y/N" }

    while ($true) {
        $ans = Read-Host ("{0} ({1})" -f $Question, $defTxt)

        if ([string]::IsNullOrWhiteSpace($ans)) {
            return ($Default -eq "Y")
        }

        switch ($ans.Trim().ToLower()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { fncPrintMessage "Please enter Y or N." "warning" }
        }
    }
}

# ------------------------------------------------------------
# Function: fncPause
# ------------------------------------------------------------
function fncPause {
    param([string]$Message = "Press Enter to continue")

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" "Pause invoked" } } catch {}

    Read-Host $Message | Out-Null
}

function fncTryGetRegistryValue {

    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    fncLog "DEBUG" ("Registry lookup requested: {0} -> {1}" -f $Path, $Name)

    try {

        if (-not (Test-Path $Path)) { return $Default }

        $item = Get-ItemProperty $Path -ErrorAction Stop
        if ($null -eq $item) { return $Default }

        if ($item.PSObject.Properties.Name -notcontains $Name) {
            return $Default
        }

        return $item.$Name
    }
    catch {
        fncLogException $_.Exception "fncTryGetRegistryValue"
        return $Default
    }
}

function fncInitFindings {

    fncLog "DEBUG" "Initialising findings container"
    $global:ProberState.Findings = @{}
}

function fncSafeArray {
    param($Value)

    if ($null -eq $Value) { return @() }

    return @($Value)
}

function fncSafeCount {

    param($Value)

    if ($null -eq $Value) { return 0 }

    try {
        return @($Value | Where-Object { $_ -ne $null }).Count
    }
    catch {
        return 0
    }
}

function fncSafeString { 
    param($Value) 
    if ($null -eq $Value) { 
        return "" 
    } return [string]$Value 
}

# Cache for fncCommandExists - only positive (found) results are cached.
# Negative results are NOT cached so lazy-loaded modules are detected after load.
$script:_cmdExistsCache = @{}

function fncCommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:_cmdExistsCache[$Name]) { return $true }
    $found = [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
    if ($found) { $script:_cmdExistsCache[$Name] = $true }
    return $found
}

function fncSafePrintMessage {
    param([string]$Msg, [string]$Level = "info")

    if (fncCommandExists "fncPrintMessage") {
        fncPrintMessage $Msg $Level
        return
    }
    Write-Host $Msg
}

function fncSafePause {
    if (fncCommandExists "fncRenderPause") { fncRenderPause; return }
    Write-Host ""
    Read-Host "Press Enter to continue" | Out-Null
}

function fncSafeRenderHeader {
    if (fncCommandExists "fncRenderHeader") { fncRenderHeader; return }
}

function fncSafeSectionHeader {
    param([string]$Title)

    if (fncCommandExists "fncRenderSectionHeader") {
        fncRenderSectionHeader -Title $Title
        return
    }
    fncSafeDivider
    Write-Host ("==== {0} ====" -f $Title)
}

function fncSafeDivider {
    if (fncCommandExists "fncRenderDivider") { fncRenderDivider; return }
    Write-Host "==========================================="
}

function fncSafeMenuOption {
    param([string]$Key, [string]$Label)

    if (fncCommandExists "fncRenderMenuOption") {
        fncRenderMenuOption -Key $Key -Label $Label
        return
    }

    Write-Host ("[{0}] {1}" -f $Key, $Label)
}

function fncSafeBackQuit {
    if (fncCommandExists "fncRenderBackQuit") {
        fncRenderBackQuit
        return
    }

    Write-Host "[B] Back"
    Write-Host "[Q] Quit"
}

function fncRiskColour {

    param([string]$Risk)

    switch ($Risk) {

        "Safe" { return "Green" }
        "Low" { return "DarkGreen" }
        "Medium" { return "Yellow" }
        "High" { return "DarkRed" }
        "Dangerous" { return "Magenta" }

        default { return "Gray" }
    }
}

function fncPrintRisk {

    param(
        [string]$Risk,
        [string]$Reason
    )

    $colour = fncRiskColour $Risk

    if ([string]::IsNullOrWhiteSpace($Reason)) {
        fncSafeDivider
        fncWriteColour ("Risk: {0}" -f $Risk) $colour
    }
    else {
        fncWriteColour ("Risk: {0} ({1})" -f $Risk, $Reason) $colour
    }
}

function fncMaturityColour {

    param([string]$Level)

    switch ($Level) {

        "Stable" { return "Green" }
        "Beta" { return "Yellow" }
        "Experimental" { return "DarkYellow" }
        "Deprecated" { return "Red" }

        default { return "Gray" }
    }
}

function fncStrategyColour {

    param([string]$Strategy)

    switch ($Strategy) {

        "Offensive" { return "Red" }
        "Defensive" { return "Cyan" }

        default { return "Gray" }
    }
}

function fncOSColour {

    param([string]$OS)

    switch ($OS) {

        "Windows" { return "Blue" }
        "Linux" { return "DarkYellow" }
        "macOS" { return "White" }
        "Cloud" { return "Cyan" }

        default { return "DarkGray" }
    }
}

function fncSaveExecutionHistory {

    $path = Join-Path $global:ProberState.Runtime.RunLogDir "history.json"

    $json = $global:ProberState.ExecutionHistory |
    ConvertTo-Json -Depth 5

    $json | Out-File $path -Encoding UTF8
}

function fncReadJsonFileSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Default = $null
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $Default }

        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }

        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $Default
    }
}

function fncWriteJsonFileSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object,
        [int]$Depth = 15
    )

    try {
        $json = $Object | ConvertTo-Json -Depth $Depth
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8 -Force
        return $true
    }
    catch {
        return $false
    }
}

function fncTryParseVersion {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $m = [regex]::Match($Text.Trim(), '^\s*(\d+(\.\d+){0,4})')
    if (-not $m.Success) { return $null }

    try { return [version]$m.Groups[1].Value } catch { return $null }
}

function fncSafeHasProp {
    param(
        [Parameter(Mandatory = $true)]$Obj,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Obj) { return $false }
    try { return ($Obj.PSObject.Properties.Name -contains $Name) } catch { return $false }
}

function fncSafeGetProp {
    param(
        [Parameter(Mandatory = $true)]$Obj,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    if (-not (fncSafeHasProp $Obj $Name)) { return $Default }
    try { return $Obj.$Name } catch { return $Default }
}


function fncGetUtcNowIso {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function fncFormatColumn {
    param(
        [string]$Text,
        [int]$Width
    )

    if ($null -eq $Text) { $Text = "" }

    $t = [string]$Text

    if ($t.Length -gt $Width) {
        return $t.Substring(0, $Width - 3) + "..."
    }

    return $t.PadRight($Width)
}

# ---------------------------------------------------------------
# Function: fncGetAVSafePath
# Purpose : Returns the best available directory for dropping
#           files that AV/EDR is unlikely to delete on creation.
#           Enumerates Defender exclusion paths and returns the
#           first one that is present and user-writable.
#           Falls back to $env:TEMP if none are found.
#           Result is cached in ProberState so repeat calls
#           within a run are instantaneous.
# Usage   : $dir = fncGetAVSafePath
#           $file = Join-Path (fncGetAVSafePath) "output.dmp"
# ---------------------------------------------------------------
function fncGetAVSafePath {

    # Return cached value from this run if already resolved
    try {
        $cached = fncSafeGetProp $global:ProberState "_AVSafePath" $null
        if ($cached -and (Test-Path $cached)) {
            fncLog "DEBUG" ("fncGetAVSafePath returning cached: {0}" -f $cached)
            return $cached
        }
    }
    catch {}

    $safePath = try { [System.IO.Path]::GetTempPath() } catch { if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { "/tmp" } }

    try {
        $defPrefs = Get-MpPreference -ErrorAction Stop

        foreach ($excPath in @($defPrefs.ExclusionPath | Where-Object { $_ })) {

            if (-not (Test-Path $excPath)) { continue }

            # Confirm the path is writable by the current process
            $probe = Join-Path $excPath ([System.IO.Path]::GetRandomFileName())
            try {
                [System.IO.File]::WriteAllText($probe, "x")
                Remove-Item $probe -Force -ErrorAction SilentlyContinue
                $safePath = $excPath
                fncLog "INFO" ("fncGetAVSafePath found Defender-excluded writable path: {0}" -f $safePath)
                break
            }
            catch {}
        }
    }
    catch {
        fncLog "DEBUG" ("fncGetAVSafePath could not query Defender exclusions: {0}" -f $_.Exception.Message)
    }

    # Cache in ProberState for the lifetime of this run
    try {
        if (fncSafeHasProp $global:ProberState "_AVSafePath") {
            $global:ProberState._AVSafePath = $safePath
        }
        else {
            $global:ProberState | Add-Member -MemberType NoteProperty -Name "_AVSafePath" -Value $safePath -Force
        }
    }
    catch {}

    fncLog "DEBUG" ("fncGetAVSafePath resolved to: {0}" -f $safePath)
    return $safePath
}

function fncIsCacheFresh {
    param(
        [string]$Path,
        [int]$MaxAgeHours = 24
    )

    if (-not (Test-Path $Path)) { return $false }

    $age = (Get-Date) - (Get-Item $Path).LastWriteTime
    return ($age.TotalHours -lt $MaxAgeHours)
}

Export-ModuleMember -Function @(
    "fncGetScriptDirectory",
    "fncGetCurrentOS",
    "fncIsAdmin",
    "fncCreateTempDir",
    "fncCleanupTempDir",
    "fncGetEnvProfile",
    "fncAskYesNo",
    "fncPause",
    "fncTryGetRegistryValue",
    "fncInitFindings",
    "fncRiskColour",
    "fncPrintRisk",
    "fncMaturityColour",
    "fncStrategyColour",
    "fncOSColour",
    "fncSaveExecutionHistory",
    "fncSafeCount",
    "fncSafeArray",
    "fncSafeString",
    "fncCommandExists",
    "fncSafePrintMessage",
    "fncSafePause",
    "fncSafeRenderHeader",
    "fncSafeSectionHeader",
    "fncSafeDivider",
    "fncSafeMenuOption",
    "fncSafeBackQuit",
    "fncSafeHasProp",
    "fncSafeGetProp",
    "fncGetUtcNowIso",
    "fncReadJsonFileSafe",
    "fncWriteJsonFileSafe",
    "fncFormatColumn",
    "fncIsCacheFresh",
    "fncTryParseVersion",
    "fncGetAVSafePath"
)
