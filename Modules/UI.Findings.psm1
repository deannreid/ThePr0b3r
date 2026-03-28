# ================================================================
# Module  : UI.Findings.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncShowFindings {

    $findings = fncSafeArray $global:ProberState.Findings.Values

    if ((fncSafeCount $findings) -eq 0) {
        fncSafePrintMessage "No findings recorded." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Findings Viewer"
        fncSafeDivider

        fncSafeMenuOption "1" "All"
        Write-Host ""
        fncSafeMenuOption "2" "Critical"
        fncSafeMenuOption "3" "High"
        fncSafeMenuOption "4" "Medium"
        fncSafeMenuOption "5" "Low"
        fncSafeMenuOption "6" "Info"

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select filter"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "1" { fncPrintFindings -SeverityFilter "All" }
            "2" { fncPrintFindings -SeverityFilter "Critical" }
            "3" { fncPrintFindings -SeverityFilter "High" }
            "4" { fncPrintFindings -SeverityFilter "Medium" }
            "5" { fncPrintFindings -SeverityFilter "Low" }
            "6" { fncPrintFindings -SeverityFilter "Info" }

            "B" { return }
            "Q" { return }
        }

        fncSafePause
    }
}

function fncExportFindings {
    # Delegate to the full CSV exporter in Export.psm1
    if (fncCommandExists "fncExportFindingsToCsv") {
        fncExportFindingsToCsv
    }
    else {
        fncSafePrintMessage "Export module not loaded." "warning"
    }

    fncSafePause
}

function fncShowFindingsMenu {

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Findings"
        fncSafeMenuOption "1" "View Findings"
        Write-Host ""
        fncSafeMenuOption "2" "Export to CSV"
        fncSafeMenuOption "3" "Export to HTML"
        fncSafeMenuOption "4" "Export to JSON"
        Write-Host ""
        fncSafeMenuOption "B" "Main Menu"
        fncSafeMenuOption "Q" "Quit"

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "1" { fncShowFindings }

            "2" {
                if (fncCommandExists "fncExportFindingsToCsv") {
                    fncExportFindingsToCsv
                }
                else {
                    fncSafePrintMessage "Export module not loaded." "warning"
                }
                fncSafePause
            }

            "3" {
                if (fncCommandExists "fncExportFindingsToHtml") {
                    fncExportFindingsToHtml
                }
                else {
                    fncSafePrintMessage "Export module not loaded." "warning"
                }
                fncSafePause
            }

            "4" {
                if (fncCommandExists "fncExportFindingsToJson") {
                    fncExportFindingsToJson
                }
                else {
                    fncSafePrintMessage "Export module not loaded." "warning"
                }
                fncSafePause
            }

            "B" { return }
            "Q" { return }
        }
    }
}

Export-ModuleMember -Function @(
    "fncShowFindings",
    "fncExportFindings",
    "fncShowFindingsMenu"
)
