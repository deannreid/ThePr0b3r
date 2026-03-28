# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0040"; Name = "Impact"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0040/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-119"; Name = "Improper Restriction of Operations within the Bounds of a Memory Buffer"; Url = "https://cwe.mitre.org/data/definitions/119.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-3"; Name = "Malicious Code Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_CONTROLLED_FOLDER_ACCESS_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckControlledFolderAccess
# Purpose : Evaluate Defender Controlled Folder Access posture
# ================================================================
function fncCheckControlledFolderAccess {

    fncSafeSectionHeader "Controlled Folder Access (CFA) Validation"
    $Risk = "Low"
    $RiskReason = "Queries Defender Controlled Folder Access configuration via Get-MpPreference which may appear in Defender telemetry"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating Defender ransomware protection posture..." "info"
    Write-Host ""

    $testId = "CONTROLLED-FOLDER-ACCESS-CHECK"

    $mpStatus = $null
    $cfaMode = $null
    $allowedApps = @()
    $protectedFolders = @()

    # ------------------------------------------------------------
    # Query Defender Status
    # ------------------------------------------------------------
    try {

        $mpStatus = Get-MpPreference -ErrorAction Stop
        $cfaMode = $mpStatus.EnableControlledFolderAccess
        $allowedApps = $mpStatus.ControlledFolderAccessAllowedApplications
        $protectedFolders = $mpStatus.ControlledFolderAccessProtectedFolders

        if ($cfaMode -eq 1) {
            fncTestMessage ("Controlled Folder Access Mode: {0}" -f $cfaMode) "proten"
        }
        elseif ($cfaMode -eq 2) {
            fncTestMessage ("Controlled Folder Access Mode: {0}" -f $cfaMode) "warning"
        }
        else {
            fncTestMessage ("Controlled Folder Access Mode: {0}" -f $cfaMode) "specpriv"
        }

    }
    catch {

        fncTestMessage "Unable to query Defender preferences." "warning"

        fncSubmitFinding `
            -Id "CFA_UNABLE_TO_QUERY" `
            -Title "Unable to Validate Controlled Folder Access" `
            -Category "Application Control" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Get-MpPreference failed. Defender state unknown." `
            -Recommendation "Verify Defender service state and required permissions." `
            -Evidence @("Get-MpPreference query failed") `
            -SourceTests @($testId) `
            -Exploitation "Unknown CFA state may leave system exposed to ransomware." `
            -Remediation "Ensure Defender is installed and operational."

        return
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Mode Interpretation
    # 0 = Disabled
    # 1 = Enabled (Block)
    # 2 = Audit Mode
    # ------------------------------------------------------------

    # Disabled
    if ($cfaMode -eq 0) {

        fncTestMessage "Controlled Folder Access is DISABLED." "specpriv"

        $exploitationText = @"
Controlled Folder Access is disabled.
Malicious processes can encrypt or modify files within:
- Documents
- Desktop
- Pictures
- Custom protected folders
This significantly increases ransomware blast radius.
Attackers do not need to bypass CFA to impact critical data.
"@

        $remediationText = @"
Enable Controlled Folder Access via:
- Group Policy
- Intune
- Defender Security Center

Deploy initially in Audit Mode, then transition to Enforced.
Validate business application compatibility before enforcement.
"@

        fncSubmitFinding `
            -Id "CFA_DISABLED" `
            -Title "Controlled Folder Access Disabled" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Not Enabled" `
            -Message "Ransomware protection via CFA is disabled." `
            -Recommendation "Enable Controlled Folder Access." `
            -Evidence @("EnableControlledFolderAccess=0") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Audit Mode
    if ($cfaMode -eq 2) {

        fncTestMessage "Controlled Folder Access is in AUDIT MODE." "warning"

        $exploitationText = @"
Controlled Folder Access is in Audit Mode.
Unauthorized modifications are logged but NOT blocked.
Ransomware can still encrypt protected folders.
Audit provides detection but no prevention.
"@

        $remediationText = @"
Review CFA audit logs in:
Microsoft-Windows-Windows Defender/Operational

After validating legitimate applications,
transition CFA to Enforced mode.
"@

        fncSubmitFinding `
            -Id "CFA_AUDIT_ONLY" `
            -Title "Controlled Folder Access Audit Only" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Audit Mode" `
            -Message "CFA deployed but not enforcing file protection." `
            -Recommendation "Transition CFA to enforced blocking mode." `
            -Evidence @("EnableControlledFolderAccess=2") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Enforced
    if ($cfaMode -eq 1) {

        fncTestMessage "Controlled Folder Access is ENFORCED (Blocking Mode)." "proten"

        if ($allowedApps.Count -gt 0) {
            fncTestMessage ("Allowed Applications Count: {0}" -f $allowedApps.Count) "active"
        }

        if ($protectedFolders.Count -gt 0) {
            fncTestMessage ("Custom Protected Folders Count: {0}" -f $protectedFolders.Count) "active"
        }

        $exploitationText = @"
Controlled Folder Access is actively blocking unauthorized file modifications.
Ransomware attempting to encrypt protected directories will be denied.
Attackers must:
- Disable Defender
- Bypass tamper protection
- Gain administrative control
This significantly reduces ransomware impact surface.
"@

        $remediationText = @"
Maintain CFA enforcement.
Review allowed applications regularly to ensure no excessive exclusions.
Ensure:
- Defender real-time protection enabled
- Tamper protection enabled
- Logs monitored for blocked attempts
"@

        fncSubmitFinding `
            -Id "CFA_ENFORCED" `
            -Title "Controlled Folder Access Enforced" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Enforced" `
            -Message ("CFA enforced. AllowedApps={0}, CustomFolders={1}" -f $allowedApps.Count, $protectedFolders.Count) `
            -Recommendation "Maintain CFA enforcement and monitor logs." `
            -Evidence @(
            ("AllowedApps={0}" -f $allowedApps.Count),
            ("CustomFolders={0}" -f $protectedFolders.Count)
        ) `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Fallback
    fncTestMessage "Controlled Folder Access state unclear." "warning"

    fncSubmitFinding `
        -Id "CFA_UNKNOWN" `
        -Title "Controlled Folder Access State Unclear" `
        -Category "Application Control" `
        -Severity "Low" `
        -Status "Unknown" `
        -Message "CFA registry value present but state unclear." `
        -Recommendation "Validate via Defender Security Center." `
        -Evidence @("EnableControlledFolderAccess=$cfaMode") `
        -SourceTests @($testId) `
        -Exploitation "Unclear CFA posture may leave ransomware exposure." `
        -Remediation "Confirm Defender configuration."
}

Export-ModuleMember -Function @("fncCheckControlledFolderAccess", "fncGetMappings_CONTROLLED_FOLDER_ACCESS_CHECK")