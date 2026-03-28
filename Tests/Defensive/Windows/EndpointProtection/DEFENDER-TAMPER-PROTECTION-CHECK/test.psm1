# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-3"; Name = "Malicious Code Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_DEFENDER_TAMPER_PROTECTION_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckDefenderTamperProtection
# Purpose : Determine if Microsoft Defender Tamper Protection is enabled
# Notes   : Requires Administrator privileges
# ================================================================
function fncCheckDefenderTamperProtection {

    fncPrintSectionHeader "Microsoft Defender Tamper Protection Validation"

    $Risk = "Low"
    $RiskReason = "Performs read-only query of Microsoft Defender configuration using Get-MpComputerStatus"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking Defender Tamper Protection status..." "info"

# ------------------------------------------------------------
# Administrator Check
# ------------------------------------------------------------

    $isAdmin = $false

    try {

        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)

        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    } catch {}

    if (-not $isAdmin) {

        fncTestMessage "Administrator privileges required to validate Defender tamper protection." "disabled"

$exploitationText = @"
This validation requires administrative privileges to query Microsoft Defender
system status.

If attackers obtain administrative privileges they may attempt to disable
security controls including Microsoft Defender protections.
"@

$remediationText = @"
Run this validation with administrative privileges.

Ensure Defender configuration is centrally managed and monitor changes
to security settings using:

- Defender event logs
- Endpoint Detection and Response telemetry
- Centralised security monitoring
"@

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "ADMIN_REQUIRED_TAMPER")) `
            -Category "Defense Evasion" `
            -Title "Defender Tamper Protection Check Requires Admin" `
            -Severity "Low" `
            -Status "Mixed / Unclear" `
            -Message "Administrator privileges required to validate tamper protection status." `
            -Recommendation "Run the check with administrative privileges." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Query Defender Status
# ------------------------------------------------------------

    fncTestMessage "Querying Defender system status..." "info"

    $tamperEnabled = $false

    try {

        $status = Get-MpComputerStatus

        fncTestMessage "Defender status retrieved successfully." "active"

        if ($status.IsTamperProtected) {
            $tamperEnabled = $true
        }

    } catch {

        fncTestMessage "Unable to query Defender status." "warning"
        return
    }

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/001/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection" "link"

# ------------------------------------------------------------
# Tamper Protection Enabled
# ------------------------------------------------------------

    if ($tamperEnabled) {

        fncTestMessage "Defender Tamper Protection is enabled." "proten"

$exploitationText = @"
Microsoft Defender Tamper Protection is enabled.

Tamper Protection prevents unauthorized modification of critical
Defender security settings including:

- Real-Time Protection
- Antivirus exclusions
- Security configuration changes
- Defender service settings

This significantly reduces the ability for attackers or malware
to disable security protections.
"@

$remediationText = @"
No remediation required.

Maintain centralized Defender configuration and ensure tamper
protection remains enabled across all managed endpoints.

Best practice:

- Manage Defender settings via Group Policy or MDM
- Monitor Defender health status centrally
- Alert on attempts to modify security settings
"@

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "TAMPER_ENABLED")) `
            -Category "Defense Evasion" `
            -Title "Defender Tamper Protection Enabled" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "Microsoft Defender Tamper Protection is enabled." `
            -Recommendation "Maintain centralized Defender management." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Tamper Protection Disabled
# ------------------------------------------------------------

    fncTestMessage "Defender Tamper Protection is NOT enabled." "specpriv"

$exploitationText = @"
Microsoft Defender Tamper Protection is disabled.

Without Tamper Protection, attackers with administrative privileges
may modify or disable Defender security settings.

This may allow attackers to:

- Disable real-time protection
- Add malicious exclusion paths
- Stop antivirus services
- Deploy malware without detection

Attackers frequently disable security controls before deploying
payloads or persistence mechanisms.
"@

$remediationText = @"
Enable Microsoft Defender Tamper Protection.

Recommended actions:

1) Enable Tamper Protection through Microsoft Defender Security Center.
2) Enforce Defender configuration through MDM or Group Policy.
3) Monitor for Defender configuration changes.
4) Ensure endpoint security telemetry is centrally monitored.

Tamper Protection should remain enabled across all managed endpoints.
"@

    fncSubmitFinding `
        -Id ("DEFENDER-" + (fncShortHashTag "TAMPER_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "Defender Tamper Protection Disabled" `
        -Severity "Medium" `
        -Status "Detected" `
        -Message "Microsoft Defender Tamper Protection is disabled." `
        -Recommendation "Enable Tamper Protection through Defender Security Center." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

}

Export-ModuleMember -Function @("fncCheckDefenderTamperProtection", "fncGetMappings_DEFENDER_TAMPER_PROTECTION_CHECK")