# ================================================================
# Module  : UI.Render.psm1
# ================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncRenderHeader {

    param(
        [switch]$MainMenu
    )

    if (-not $global:ProberState.Config.DEBUG) {
        Clear-Host
    }

    try {
        $isBlue = (fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")) -eq "blue"

        if ($global:Banner) {
            $colour = if ($isBlue) { [System.ConsoleColor]::Blue } else { [System.ConsoleColor]::DarkRed }
            fncWriteColour ($global:Banner -f (fncSafeString $global:CurrentBlurb)) $colour
        }

        # ── Resolve identity ──────────────────────────────────────────
        $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME }
                    elseif ($env:HOSTNAME) { $env:HOSTNAME }
                    else { try { (& bash -c "hostname 2>/dev/null").Trim() } catch { "unknown" } }

        $userName = if ($env:USERNAME) { $env:USERNAME }
                    elseif ($env:USER) { $env:USER }
                    else { try { (& bash -c "id -un 2>/dev/null").Trim() } catch { "unknown" } }

        $domain = ""
        try {
            if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
                $domain = $env:USERDOMAIN
            }
        }
        catch {}

        # ── Resolve OS + privilege ────────────────────────────────────
        $isElevated   = $false
        $isNonWindows = $false
        $isMac        = $false
        try {
            if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
                if ($IsLinux)  { $isNonWindows = $true }
                if ($IsMacOS)  { $isNonWindows = $true; $isMac = $true }
            }
        }
        catch {}

        $osLabel = if ($isMac) { "macOS" } elseif ($isNonWindows) { "Linux" } else { "Windows" }

        try {
            if ($isNonWindows) {
                $uid = (& bash -c "id -u 2>/dev/null").Trim()
                $isElevated = ($uid -eq "0")
            }
            else {
                $id = [Security.Principal.WindowsIdentity]::GetCurrent()
                $p  = New-Object Security.Principal.WindowsPrincipal($id)
                $isElevated = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            }
        }
        catch {}

        $privLabel  = if ($isElevated) { "[ADMIN]" } else { "[USER]" }
        $privColour = if ($isElevated) { [System.ConsoleColor]::Red } else { [System.ConsoleColor]::Green }

        # ── Resolve strategy / env ────────────────────────────────────
        $strategy   = fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")
        $envProfile = fncSafeString (fncSafeGetProp $global:ProberState "EnvProfile" "Unknown")
        $stratLabel = if ($isBlue) { "[DEFENSIVE]" } else { "[OFFENSIVE]" }
        $stratCol   = if ($isBlue) { [System.ConsoleColor]::Blue } else { [System.ConsoleColor]::Red }

        # ── Resolve test count + short RunId ─────────────────────────
        $testCount = 0
        try { $testCount = fncSafeCount (fncSafeArray $global:ProberState.Tests) } catch {}

        $shortRun = ""
        try { $shortRun = ([string]$global:ProberState.RunContext.RunId).Substring(0, 8) } catch {}

        # ── Single status line ────────────────────────────────────────
        Write-Host ""

        fncWriteColour "  " White -NoNewLine
        fncWriteColour $hostName Yellow -NoNewLine
        if ($domain) {
            fncWriteColour (" ({0})" -f $domain) DarkGray -NoNewLine
        }
        fncWriteColour "  @  " DarkGray -NoNewLine
        fncWriteColour $userName Cyan -NoNewLine
        fncWriteColour "  " White -NoNewLine
        fncWriteColour $privLabel $privColour -NoNewLine
        fncWriteColour "  |  " DarkGray -NoNewLine
        fncWriteColour $osLabel DarkCyan -NoNewLine
        fncWriteColour "  |  " DarkGray -NoNewLine
        fncWriteColour $envProfile White -NoNewLine
        fncWriteColour "  |  " DarkGray -NoNewLine
        fncWriteColour $stratLabel $stratCol -NoNewLine
        fncWriteColour "  |  " DarkGray -NoNewLine
        fncWriteColour ([string]$testCount) Cyan -NoNewLine
        fncWriteColour " tests" DarkGray -NoNewLine
        if ($shortRun) {
            fncWriteColour "  |  " DarkGray -NoNewLine
            fncWriteColour ("run:{0}" -f $shortRun) DarkGray
        }
        else {
            Write-Host ""
        }

        Write-Host ""
    }
    catch {
        Write-Host ""
        Write-Host "  [!] Header failed to render: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  [!] If modules did not load, re-run with:" -ForegroundColor Yellow
        Write-Host "      powershell.exe -ExecutionPolicy Bypass -File .\thePr0b3r.ps1" -ForegroundColor Cyan
        Write-Host ""
    }

    if ($MainMenu) {
        $noOp = $false
        try { $noOp = [bool]$global:ProberState.Config.NoOperator } catch {}
        if (-not $noOp -and (fncCommandExists "fncPrintOperatorRiskBanner")) {
            fncPrintOperatorRiskBanner
        }
    }
}

function fncPrintStatus {

    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter()][object]$Value
    )

    $Value = fncSafeString $Value

    if (fncCommandExists "fncWriteColour") {
        fncWriteColour ("  {0,-20}: " -f $Label) ([System.ConsoleColor]::White) -NoNewLine
        fncWriteColour $Value ([System.ConsoleColor]::Cyan)
    }
    else {
        Write-Host ("  {0,-20}: {1}" -f $Label, $Value)
    }
}

function fncRenderSectionHeader {
    param([Parameter(Mandatory)][string]$Title)

    $isBlue = $false
    try {
        $isBlue = (fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")) -eq "blue"
    }
    catch {}

    $colour = if ($isBlue) { [System.ConsoleColor]::Blue } else { [System.ConsoleColor]::Red }

    if (fncCommandExists "fncWriteColour") {
        fncWriteColour ("===== [ {0} ] =====" -f $Title) $colour
    }
    else {
        Write-Host ("[ {0} ]" -f $Title)
    }

    Write-Host ""
}

function fncRenderEnvironmentLine {

    $envProfile = "Unknown"

    try {
        if ($global:ProberState -and $global:ProberState.EnvProfile) {
            $envProfile = fncSafeString $global:ProberState.EnvProfile
        }
    }
    catch {}

    if (fncCommandExists "fncPrintMessage") {
        fncPrintMessage ("Environment Profile: {0}" -f $envProfile) "info"
    }
    else {
        Write-Host ("Environment Profile: {0}" -f $envProfile)
    }
}

function fncRenderDivider {
    Write-Host "==========================================="
}

function fncRenderMenuOption {
    param(
        [string]$Key,
        [string]$Label
    )

    if (fncCommandExists "fncWriteColour") {

        fncWriteColour ("  {0,-3}" -f ("[" + $Key + "]")) ([System.ConsoleColor]::Yellow) -NoNewLine
        fncWriteColour (" {0}" -f $Label) ([System.ConsoleColor]::White)

    }
    else {

        Write-Host ("  [{0}] {1}" -f $Key, $Label)

    }
}

function fncRenderBackQuit {

    Write-Host "[B] Back"
    Write-Host "[Q] Quit"
}

function fncRenderPause {

    Write-Host ""
    try { Read-Host "Press Enter to continue" | Out-Null }
    catch {}
}

function fncRenderTestEntry {

    param(
        [int]$Index,
        [object]$Test,
        [bool]$Unavailable = $false
    )

    $name = ""
    $requiresAdmin = $false
    $isDomainTest = $false
    $maturity = "Experimental"
    $risk = "Low"
    $os = "Any"
    $strategy = "Defensive"
    $hasRun = $false

    try {

        $name = fncSafeString $Test.Name
        $requiresAdmin = [bool](fncSafeGetProp $Test "RequiresAdmin" $false)

        $maturity = fncSafeGetProp $Test "Maturity" "Experimental"
        $risk = fncSafeGetProp $Test "Risk" "Low"
        $os = fncSafeString (fncSafeGetProp $Test "OS" "Any")
        $strategy = fncSafeString (fncSafeGetProp $Test "Strategy" "Defensive")

        $scopes = @(fncSafeArray (fncSafeGetProp $Test "Scopes" @()))
        $isDomainTest = $scopes -contains "Domain"
        $isEntraTest  = $scopes -contains "Entra"
        $isAzureTest  = $scopes -contains "Azure"
        $isAWSTest    = $scopes -contains "AWS"

        if ($global:ProberState.ExecutionHistory -and $global:ProberState.ExecutionHistory.ContainsKey($Test.Id)) {
            $hasRun = $true
        }

    }
    catch {}

    if ($Unavailable) {
        if (fncCommandExists "fncWriteColour") {
            fncWriteColour "  [ -]" DarkGray -NoNewLine
            fncWriteColour (" {0}" -f $name) DarkGray
        }
        else {
            Write-Host ("  [ -] {0}" -f $name)
        }
        return
    }

    if (fncCommandExists "fncWriteColour") {

        $nameColour = "White"
        if ($hasRun) { $nameColour = "DarkGray" }

        # Fixed column widths
        $nameWidth = 55
        $matWidth = 12
        $riskWidth = 10
        $osWidth = 11
        $stratWidth = 12

        $badgeWidth = 0
        if ($requiresAdmin) { $badgeWidth += 4 }  # " [A]"
        if ($isDomainTest)  { $badgeWidth += 4 }  # " [D]"
        if ($isEntraTest)   { $badgeWidth += 4 }  # " [E]"
        if ($isAzureTest)   { $badgeWidth += 5 }  # " [Az]"
        if ($isAWSTest)     { $badgeWidth += 5 }  # " [Aw]"
        $paddedName = (" {0}" -f $name).PadRight($nameWidth - $badgeWidth)
        $matTag = ("[{0}]" -f $maturity.ToUpper()).PadRight($matWidth)
        $riskTag = ("[{0}]" -f $risk.ToUpper()).PadRight($riskWidth)
        $osTag = ("[{0}]" -f $os.ToUpper()).PadRight($osWidth)
        $stratTag = ("[{0}]" -f $strategy.ToUpper()).PadRight($stratWidth)

        # Number
        fncWriteColour ("  [{0:00}]" -f $Index) Yellow -NoNewLine

        # Name with inline scope/admin badges
        fncWriteColour $paddedName $nameColour -NoNewLine
        if ($requiresAdmin) { fncWriteColour " [A]"  Red        -NoNewLine }
        if ($isDomainTest)  { fncWriteColour " [D]"  Cyan       -NoNewLine }
        if ($isEntraTest)   { fncWriteColour " [E]"  Magenta    -NoNewLine }
        if ($isAzureTest)   { fncWriteColour " [Az]" Blue       -NoNewLine }
        if ($isAWSTest)     { fncWriteColour " [Aw]" DarkYellow -NoNewLine }

        # Maturity
        fncWriteColour $matTag (fncMaturityColour $maturity) -NoNewLine

        # Risk
        fncWriteColour $riskTag (fncRiskColour $risk) -NoNewLine

        # OS
        fncWriteColour $osTag (fncOSColour $os) -NoNewLine

        # Strategy
        fncWriteColour $stratTag (fncStrategyColour $strategy)

    }
    else {

        $suffix = ""
        $suffix += (" [{0}]" -f $maturity.ToUpper())
        $suffix += (" [{0}]" -f $risk.ToUpper())
        $suffix += (" [{0}]" -f $os.ToUpper())
        $suffix += (" [{0}]" -f $strategy.ToUpper())

        $badges = ""
        if ($requiresAdmin) { $badges += " [A]" }
        if ($isDomainTest)  { $badges += " [D]" }
        if ($isEntraTest)   { $badges += " [E]" }
        if ($isAzureTest)   { $badges += " [Az]" }
        if ($isAWSTest)     { $badges += " [Aw]" }
        $displayName = if ($badges) { "{0}{1}" -f $name, $badges } else { $name }

        if ($hasRun) {
            Write-Host ("[{0:00}] {1}{2} (completed)" -f $Index, $displayName, $suffix)
        }
        else {
            Write-Host ("[{0:00}] {1}{2}" -f $Index, $displayName, $suffix)
        }
    }
}

Export-ModuleMember -Function @(
    "fncRenderHeader",
    "fncPrintStatus",
    "fncRenderSectionHeader",
    "fncRenderEnvironmentLine",
    "fncRenderDivider",
    "fncRenderMenuOption",
    "fncRenderBackQuit",
    "fncRenderPause",
    "fncRenderTestEntry"
)
