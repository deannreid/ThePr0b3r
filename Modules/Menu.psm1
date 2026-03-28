# ================================================================
# Module  : Menu.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncRenderMenuOptionWip {

    param(
        [string]$Key,
        [string]$Label
    )

    fncWriteColour ("  {0,-3}" -f ("[" + $Key + "]")) Yellow -NoNewLine
    fncWriteColour (" {0}" -f $Label) White -NoNewLine
    fncWriteColour "  [WIP]" DarkYellow
}

function fncRenderMenuOptionNA {
    param(
        [string]$Key,
        [string]$Label,
        [string]$Reason = "unavailable"
    )

    fncWriteColour ("  [{0}]" -f $Key) DarkGray -NoNewLine
    fncWriteColour (" {0}" -f $Label) DarkGray -NoNewLine
    fncWriteColour ("  [{0}]" -f $Reason) DarkGray
}

# Returns "os-unavailable", "not-found", or "" (loaded/available)
function fncGetModuleStatus {
    param([string]$ModuleName)

    try {
        $deferred = $global:ProberState.Runtime.DeferredModules
        if ($deferred -and $deferred.ContainsKey($ModuleName)) {
            return $deferred[$ModuleName]
        }
    }
    catch {}

    return ""
}

# Attempts to lazy-load a deferred optional module. Returns $true on success.
function fncTryLoadModule {
    param([string]$ModuleName)

    # Already loaded
    $modBase = [System.IO.Path]::GetFileNameWithoutExtension($ModuleName)
    if (Get-Module -Name $modBase -ErrorAction SilentlyContinue) { return $true }

    $status = fncGetModuleStatus $ModuleName
    if ($status -eq "os-unavailable" -or $status -eq "not-found") { return $false }

    $root = ""
    try { $root = $global:ProberState.Runtime.ModulesRoot } catch {}
    if ([string]::IsNullOrWhiteSpace($root)) { return $false }

    $path = Join-Path $root $ModuleName
    if (-not (Test-Path $path)) { return $false }

    try {
        Import-Module $path -Force -ErrorAction Stop | Out-Null
        # Remove from deferred if it was there
        try { $global:ProberState.Runtime.DeferredModules.Remove($ModuleName) } catch {}
        return $true
    }
    catch { return $false }
}

function fncShowMainMenu {

    try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Entering fncShowMainMenu loop" } } catch {}

    while ($true) {

        if (fncCommandExists "fncRenderHeader") {
            fncRenderHeader -MainMenu
        }

        # Check live connection state each render
        $adConnected = (fncCommandExists "fncADIsConnected") -and (fncADIsConnected)
        $entraConnected = (fncCommandExists "fncEntraIsConnected") -and (fncEntraIsConnected)
        $azureConnected = (fncCommandExists "fncAzureIsConnected") -and (fncAzureIsConnected)
        $awsConnected = (fncCommandExists "fncAWSIsConnected") -and (fncAWSIsConnected)

        # CIS menu item: only shown when a benchmark file exists for this OS
        $cisBenchmark = if (fncCommandExists "fncCISGetAvailableBenchmark") {
            fncCISGetAvailableBenchmark
        }
        else {
            [pscustomobject]@{ Available = $false; Label = "" }
        }

        # Determine integration module availability (loaded vs deferred vs missing)
        $adStatus = fncGetModuleStatus "Integrations.AD.psm1"
        $entraStatus = fncGetModuleStatus "Integrations.EntraID.psm1"
        $awsStatus = fncGetModuleStatus "Integrations.AWS.psm1"
        $azureStatus = fncGetModuleStatus "Integrations.Azure.psm1"
        $cisStatus = fncGetModuleStatus "Integrations.CIS.psm1"

        Write-Host ""

        fncWriteColour "=========== TEST EXECUTION ===========" Cyan
        fncRenderMenuOption "1" ("Run Tests (Environment: {0})" -f $global:ProberState.EnvProfile)

        if ($adConnected) { fncWriteColour "  [ADT]" Cyan       -NoNewLine; fncWriteColour " AD Tests (Domain)"  White }
        if ($entraConnected) { fncWriteColour "  [ENT]" Magenta    -NoNewLine; fncWriteColour " Entra Tests"        White }
        if ($awsConnected) { fncWriteColour "  [AWT]" DarkYellow -NoNewLine; fncWriteColour " AWS Tests"          White }
        if ($azureConnected) { fncWriteColour "  [AZT]" Blue       -NoNewLine; fncWriteColour " Azure Tests"        White }

        fncRenderMenuOption "2" "Run Tests (Select Environment)"
        fncRenderMenuOption "3" "Search Test"
        fncRenderMenuOption "4" "Browse All Categories"
        fncRenderMenuOption "A" "Run All Tests"

        Write-Host ""
        fncWriteColour "=============== RESULTS ===============" Cyan
        fncRenderMenuOption "5" "View Findings"
        fncRenderMenuOption "6" "Export Findings to CSV"
        fncRenderMenuOption "7" "Export Findings to HTML"
        fncRenderMenuOption "8" "Export Findings to JSON"

        Write-Host ""
        fncWriteColour "================ MODULES ==============" Cyan

        if ($adStatus -eq "os-unavailable") {
            fncRenderMenuOptionNA "AD" "Active Directory Console" "Windows only"
        }
        elseif ($adStatus -eq "not-found") {
            fncRenderMenuOptionNA "AD" "Active Directory Console" "module not found"
        }
        else {
            fncRenderMenuOptionWip "AD" "Active Directory Console"
        }

        if ($entraStatus -eq "not-found") {
            fncRenderMenuOptionNA "EN" "Entra ID Console" "module not found"
        }
        else {
            fncRenderMenuOptionWip "EN" "Entra ID Console"
        }

        if ($awsStatus -eq "not-found") {
            fncRenderMenuOptionNA "AW" "AWS Console" "module not found"
        }
        else {
            fncRenderMenuOptionWip "AW" "AWS Console"
        }

        if ($azureStatus -eq "not-found") {
            fncRenderMenuOptionNA "AZ" "Azure Subscription Console" "module not found"
        }
        else {
            fncRenderMenuOptionWip "AZ" "Azure Subscription Console"
        }

        if ($cisStatus -eq "not-found") {
            fncRenderMenuOptionNA "CIS" "CIS Benchmark Scan" "module not found"
        }
        elseif ($cisBenchmark.Available) {
            fncRenderMenuOption "CIS" ("CIS Scan ({0})" -f $cisBenchmark.Label)
        }
        else {
            fncRenderMenuOptionNA "CIS" "CIS Benchmark Scan" "no benchmark for this OS"
        }

        Write-Host ""
        fncRenderMenuOption "R" "Reload Test Modules"
        fncRenderMenuOption "T" "Refresh Operator Telemetry"

        Write-Host ""
        fncRenderMenuOption "Q" "Quit"

        Write-Host ""

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Menu selection: {0}" -f $choice) } } catch {}

        switch ($choice.ToUpper()) {

            "1" {

                $scope = $global:ProberState.EnvProfile
                if (-not $scope) { $scope = "All" }

                $r = fncShowCategoryMenu -Scope $scope
                if ($r -eq "QUIT") { return }
            }

            "ADT" {
                if ($adConnected) {
                    $r = fncShowCategoryMenu -Scope "Domain"
                    if ($r -eq "QUIT") { return }
                }
                else {
                    fncSafePrintMessage "AD not connected." "warning"
                    fncSafePause
                }
            }

            "ENT" {
                if ($entraConnected) {
                    $r = fncShowCategoryMenu -Scope "Entra"
                    if ($r -eq "QUIT") { return }
                }
                else {
                    fncSafePrintMessage "Entra not connected." "warning"
                    fncSafePause
                }
            }

            "AWT" {
                if ($awsConnected) {
                    $r = fncShowCategoryMenu -Scope "AWS"
                    if ($r -eq "QUIT") { return }
                }
                else {
                    fncSafePrintMessage "AWS not connected." "warning"
                    fncSafePause
                }
            }

            "AZT" {
                if ($azureConnected) {
                    $r = fncShowCategoryMenu -Scope "Azure"
                    if ($r -eq "QUIT") { return }
                }
                else {
                    fncSafePrintMessage "Azure not connected." "warning"
                    fncSafePause
                }
            }

            "2" {

                $scope = fncSelectEnvironmentScope

                if (-not $scope) {
                    fncSafePrintMessage "No environment selected." "warning"
                    fncSafePause
                    continue
                }

                $r = fncShowCategoryMenu -Scope $scope
                if ($r -eq "QUIT") { return }
            }

            "3" {
                fncSearchAndRunTest
            }

            "4" {
                $r = fncShowCategoryMenu -Scope "All"
                if ($r -eq "QUIT") { return }
            }

            "A" {

                $isBlue = (fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")) -eq "blue"

                if ($isBlue) {
                    $tests = @(fncSafeArray $global:ProberState.Tests | Where-Object { $_ -and $_.Enabled -eq $true })
                    fncRunTestList -Tests $tests -Label "defensive tests"
                }
                else {
                    $r = fncShowRunAllMenu
                    if ($r -eq "QUIT") { return }
                }
            }

            "5" {

                if (fncCommandExists "fncShowFindingsMenu") {
                    fncShowFindingsMenu
                }
                else {
                    fncSafePrintMessage "Findings module missing." "warning"
                    fncSafePause
                }
            }

            "6" {

                if (fncCommandExists "fncExportFindings") {
                    fncExportFindings
                }
                else {
                    fncSafePrintMessage "Findings module missing." "warning"
                    fncSafePause
                }
            }

            "7" {

                if (fncCommandExists "fncExportFindingsToHtml") {
                    fncExportFindingsToHtml
                }
                else {
                    fncSafePrintMessage "Findings module missing." "warning"
                    fncSafePause
                }
            }

            "8" {

                if (fncCommandExists "fncExportFindingsToJson") {
                    fncExportFindingsToJson
                }
                else {
                    fncSafePrintMessage "Export module missing." "warning"
                    fncSafePause
                }
            }

            "AD" {
                $adSt = fncGetModuleStatus "Integrations.AD.psm1"
                if ($adSt -eq "os-unavailable") {
                    fncSafePrintMessage "Active Directory console requires Windows." "warning"
                    fncSafePause
                }
                elseif (-not (fncCommandExists "fncShowADConsole")) {
                    if (fncTryLoadModule "Integrations.AD.psm1") {
                        fncShowADConsole
                    }
                    else {
                        fncSafePrintMessage "AD integration module could not be loaded." "warning"
                        fncSafePause
                    }
                }
                else {
                    fncShowADConsole
                }
            }
            "EN" {
                if (-not (fncCommandExists "fncShowEntraConsole")) {
                    if (fncTryLoadModule "Integrations.EntraID.psm1") {
                        fncShowEntraConsole
                    }
                    else {
                        fncSafePrintMessage "Entra ID integration module could not be loaded." "warning"
                        fncSafePause
                    }
                }
                else {
                    fncShowEntraConsole
                }
            }
            "AW" {
                fncSafePrintMessage "AWS coming soon!" "info"
            }
            "AZ" {
                fncSafePrintMessage "Azure coming soon!" "info"
            }

            "CIS" {
                if ($cisBenchmark.Available -and (fncCommandExists "fncRunCISBenchmark")) {
                    fncRunCISBenchmark
                    fncSafePause
                }
                else {
                    fncSafePrintMessage "No CIS benchmark file found for this OS." "warning"
                    fncSafePause
                }
            }

            "R" {
                fncRescanTestModules
                fncSafePause
            }

            "T" {
                fncSafePrintMessage "Refreshing operator telemetry..." "info"
                try {
                    if (fncCommandExists "fncCollectOperatorTelemetry") {
                        $global:ProberState.OperatorTelemetry = fncCollectOperatorTelemetry
                        fncSafePrintMessage "Operator telemetry refreshed." "success"
                    }
                    else {
                        fncSafePrintMessage "Operator module not loaded." "warning"
                    }
                }
                catch {
                    fncSafePrintMessage ("Telemetry refresh failed: {0}" -f $_.Exception.Message) "error"
                }
                fncSafePause
            }

            "Q" {

                fncSafePrintMessage "Exiting THE Pr0b3r..." "warning"

                try { if (fncCommandExists "fncLog") { fncLog "INFO" "User selected Quit from main menu" } } catch {}

                return
            }

            default {

                fncSafePrintMessage "Invalid menu selection." "warning"
                fncSafePause
            }
        }
    }
}

function fncMain {

    # Initialisation (temp dir, findings, env profile, tests) is owned by
    # the runner (thePr0b3r.ps1:fncRunMenu) so it covers both console and
    # GUI paths without duplication.  fncMain's sole job here is to run the
    # interactive menu loop and tidy up on exit.

    try {

        try { if (fncCommandExists "fncLog") { fncLog "INFO" "Prober start" } } catch {}
        fncShowMainMenu
        try { if (fncCommandExists "fncLog") { fncLog "INFO" "Prober exit" } } catch {}

    }
    catch {

        fncSafePrintMessage ("Unhandled error: {0}" -f $_.Exception.Message) "error"
        try { if (fncCommandExists "fncLog") { fncLogException $_.Exception "fncMain unhandled" } } catch {}
        throw
    }
    finally {

        # Flush execution history once per session rather than per test
        try { if (fncCommandExists "fncSaveExecutionHistory") { fncSaveExecutionHistory } } catch {}

        try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Running temp directory cleanup" } } catch {}
        try { if (fncCommandExists "fncCleanupTempDir") { fncCleanupTempDir } } catch {}
    }
}

Export-ModuleMember -Function @(
    "fncMain",
    "fncShowMainMenu"
)
