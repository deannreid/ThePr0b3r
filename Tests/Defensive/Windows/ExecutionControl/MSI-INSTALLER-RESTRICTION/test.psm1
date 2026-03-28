# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1068"; Name = "Exploitation for Privilege Escalation"; Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1068/" }
        [pscustomobject]@{ Id = "T1569.002"; Name = "System Services"; Tactic = "Execution"; Url = "https://attack.mitre.org/techniques/T1569/002/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-269"; Name = "Improper Privilege Management"; Url = "https://cwe.mitre.org/data/definitions/269.html" }
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6"; Name = "Least Privilege"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-7"; Name = "Least Functionality"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_MSI_INSTALLER_RESTRICTION { return $script:Mappings }

# ================================================================
# Function: fncCheckMSIInstallerRestriction
# Purpose : Evaluate MSI / Windows Installer restriction posture
# Notes   : Console output + per-finding exploit/remediation narratives
# ================================================================
function fncCheckMSIInstallerRestriction {
    fncSafeSectionHeader "MSI Installer Restriction Assessment"
    $Risk = "Safe"
    $RiskReason = "Reads Windows Installer policy registry keys only without invoking msiexec"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating Windows Installer policy controls (DisableMSI / AlwaysInstallElevated / GPO enforcement)..." "info"
    Write-Host ""

    $testId = "MSI-INSTALLER-RESTRICTION"

    $wiPolicyHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $wiPolicyHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"

    $disableMsi = $null
    $alwaysInstallElevatedHKLM = $null
    $alwaysInstallElevatedHKCU = $null

    # ------------------------------------------------------------
    # Helper: Safe read registry value
    # ------------------------------------------------------------
    function fncReadRegDwordSafe {
        param(
            [string]$Path,
            [string]$Name
        )
        try {
            if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $null }
            $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($null -eq $p) { return $null }
            $v = $p.$Name
            if ($null -eq $v) { return $null }
            return [int]$v
        }
        catch { return $null }
    }

    # ------------------------------------------------------------
    # Enumerate signals
    # ------------------------------------------------------------
    fncTestMessage "Inspecting policy registry locations..." "info"

    $disableMsi = fncReadRegDwordSafe -Path $wiPolicyHKLM -Name "DisableMSI"
    $alwaysInstallElevatedHKLM = fncReadRegDwordSafe -Path $wiPolicyHKLM -Name "AlwaysInstallElevated"
    $alwaysInstallElevatedHKCU = fncReadRegDwordSafe -Path $wiPolicyHKCU -Name "AlwaysInstallElevated"

    $disableMsiDisplay = $(if ($null -eq $disableMsi) { "<not set>" } else { $disableMsi })

    $disableLevel = "info"
    if ($disableMsi -eq 2) { $disableLevel = "proten" }
    elseif ($disableMsi -eq 0 -or $null -eq $disableMsi) { $disableLevel = "warning" }
    elseif ($disableMsi -eq 1) { $disableLevel = "info" }

    fncTestMessage ("DisableMSI (HKLM): {0}" -f $disableMsiDisplay) $disableLevel

    fncTestMessage ("AlwaysInstallElevated (HKLM): {0}" -f $(if ($null -eq $alwaysInstallElevatedHKLM) { "<not set>" } else { $alwaysInstallElevatedHKLM })) `
    ($(if ($alwaysInstallElevatedHKLM -eq 1) { "warning" } else { "info" }))

    fncTestMessage ("AlwaysInstallElevated (HKCU): {0}" -f $(if ($null -eq $alwaysInstallElevatedHKCU) { "<not set>" } else { $alwaysInstallElevatedHKCU })) `
    ($(if ($alwaysInstallElevatedHKCU -eq 1) { "warning" } else { "info" }))

    Write-Host ""

    # ------------------------------------------------------------
    # Interpret DisableMSI
    # ------------------------------------------------------------
    $disableMsiMeaning = "Unknown"

    if ($null -eq $disableMsi) { $disableMsiMeaning = "Not configured (defaults apply)" }
    elseif ($disableMsi -eq 0) { $disableMsiMeaning = "Windows Installer enabled (no restriction)" }
    elseif ($disableMsi -eq 1) { $disableMsiMeaning = "Installer disabled for unmanaged apps only" }
    elseif ($disableMsi -eq 2) { $disableMsiMeaning = "Windows Installer disabled" }

    $interpretLevel = "info"

    if ($disableMsi -eq 2) { $interpretLevel = "proten" }
    elseif ($disableMsi -eq 0 -or $null -eq $disableMsi) { $interpretLevel = "warning" }

    fncTestMessage ("DisableMSI Interpretation: {0}" -f $disableMsiMeaning) $interpretLevel

    Write-Host ""

    # ------------------------------------------------------------
    # AlwaysInstallElevated BOTH
    # ------------------------------------------------------------
    if ($alwaysInstallElevatedHKLM -eq 1 -and $alwaysInstallElevatedHKCU -eq 1) {

        fncTestMessage "CRITICAL: AlwaysInstallElevated enabled in BOTH HKLM and HKCU." "specpriv"

        $exploitationText = @"
AlwaysInstallElevated is enabled for both HKLM and HKCU.
A standard user can execute a malicious MSI which installs with SYSTEM privileges.

Attack flow:
1. Attacker crafts MSI with custom action
2. msiexec /i payload.msi
3. Payload executes with SYSTEM privileges
"@

        $remediationText = @"
Disable AlwaysInstallElevated in both registry locations via Group Policy.

HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer

Set AlwaysInstallElevated = 0
"@

        fncSubmitFinding `
            -Id ("MSI-" + (fncShortHashTag "ALWAYS_INSTALL_ELEVATED_BOTH")) `
            -Title "AlwaysInstallElevated Enabled (Privilege Escalation Risk)" `
            -Category "Application Control" `
            -Severity "Critical" `
            -Status "Misconfigured" `
            -Message "AlwaysInstallElevated enabled in both HKLM and HKCU." `
            -Recommendation "Disable AlwaysInstallElevated via Group Policy." `
            -Evidence @(
            ("HKLM AlwaysInstallElevated={0}" -f $alwaysInstallElevatedHKLM),
            ("HKCU AlwaysInstallElevated={0}" -f $alwaysInstallElevatedHKCU)
        ) `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Single AIE
    # ------------------------------------------------------------
    if ($alwaysInstallElevatedHKLM -eq 1 -or $alwaysInstallElevatedHKCU -eq 1) {

        fncTestMessage "AlwaysInstallElevated enabled in a single hive." "warning"

        fncSubmitFinding `
            -Id ("MSI-" + (fncShortHashTag "ALWAYS_INSTALL_ELEVATED_SINGLE")) `
            -Title "AlwaysInstallElevated Enabled (Single Hive)" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "AlwaysInstallElevated enabled in one policy hive." `
            -Recommendation "Disable AlwaysInstallElevated in both HKLM and HKCU." `
            -Evidence @(
            ("HKLM={0}" -f $alwaysInstallElevatedHKLM),
            ("HKCU={0}" -f $alwaysInstallElevatedHKCU)
        ) `
            -SourceTests @($testId)

        return
    }

    # ------------------------------------------------------------
    # DisableMSI Not Restricted
    # ------------------------------------------------------------
    if ($null -eq $disableMsi -or $disableMsi -eq 0) {

        fncTestMessage "Windows Installer unrestricted." "warning"

        fncSubmitFinding `
            -Id ("MSI-" + (fncShortHashTag "DISABLEMSI_NOT_RESTRICTED")) `
            -Title "Windows Installer Not Restricted" `
            -Category "Application Control" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "DisableMSI not configured or set to 0." `
            -Recommendation "Restrict MSI installs using DisableMSI policy." `
            -Evidence @("DisableMSI=$disableMsi") `
            -SourceTests @($testId)

        return
    }

    # ------------------------------------------------------------
    # DisableMSI=1
    # ------------------------------------------------------------
    if ($disableMsi -eq 1) {

        fncTestMessage "DisableMSI=1 (Managed installs only)." "proten"

        fncSubmitFinding `
            -Id ("MSI-" + (fncShortHashTag "DISABLEMSI_MANAGED_ONLY")) `
            -Title "Windows Installer Restricted to Managed Installs" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Configured" `
            -Message "DisableMSI=1 configured." `
            -Recommendation "Maintain configuration and monitor MSI usage." `
            -Evidence @("DisableMSI=1") `
            -SourceTests @($testId)

        return
    }

    # ------------------------------------------------------------
    # DisableMSI=2
    # ------------------------------------------------------------
    if ($disableMsi -eq 2) {

        fncTestMessage "DisableMSI=2 (Windows Installer disabled)." "proten"

        fncSubmitFinding `
            -Id ("MSI-" + (fncShortHashTag "DISABLEMSI_DISABLED")) `
            -Title "Windows Installer Disabled" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Configured" `
            -Message "DisableMSI=2 configured." `
            -Recommendation "Maintain strong restriction." `
            -Evidence @("DisableMSI=2") `
            -SourceTests @($testId)

        return
    }

    # ------------------------------------------------------------
    # Unknown state
    # ------------------------------------------------------------
    fncTestMessage "Unexpected MSI policy state detected." "warning"

    fncSubmitFinding `
        -Id ("MSI-" + (fncShortHashTag "UNKNOWN_STATE")) `
        -Title "Windows Installer Policy Uncertain State" `
        -Category "Application Control" `
        -Severity "Info" `
        -Status "Unknown" `
        -Message "Unexpected Windows Installer policy value detected." `
        -Recommendation "Review GPO configuration and RSOP." `
        -Evidence @(
        ("DisableMSI={0}" -f $disableMsi),
        ("HKLM AIE={0}" -f $alwaysInstallElevatedHKLM),
        ("HKCU AIE={0}" -f $alwaysInstallElevatedHKCU)
    ) `
        -SourceTests @($testId)

    Write-Host ""
}

Export-ModuleMember -Function @("fncCheckMSIInstallerRestriction", "fncGetMappings_MSI_INSTALLER_RESTRICTION")