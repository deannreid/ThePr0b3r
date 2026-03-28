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

function fncGetMappings_DEFENDER_REALTIME_PROTECTION_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckDefenderRealtimeProtection
# Purpose : Validate Microsoft Defender Real-Time Protection status
# Notes   : Requires Administrator privileges
# ================================================================
function fncCheckDefenderRealtimeProtection {

    fncPrintSectionHeader "Defender Real-Time Protection Validation"

    $Risk = "Low"
    $RiskReason = "Performs read-only queries against Microsoft Defender configuration using Get-MpComputerStatus"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking Defender Real-Time Protection..." "info"

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

        fncTestMessage "Administrator privileges required to query Defender status." "disabled"

$exploitationText = @"
This validation requires administrative privileges to query Microsoft Defender
system status.

If attackers obtain administrative privileges, they may disable Defender
Real-Time Protection to allow malware execution without detection.
"@

$remediationText = @"
Run this validation with administrative privileges.

Ensure only trusted administrators can modify Defender configuration and
monitor Defender status changes through:

- Microsoft Defender security logs
- EDR telemetry
- Centralised security monitoring platforms
"@

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "ADMIN_REQUIRED_RTP")) `
            -Category "Defense Evasion" `
            -Title "Defender Real-Time Protection Check Requires Admin" `
            -Severity "Low" `
            -Status "Mixed / Unclear" `
            -Message "Administrator privileges required to enumerate Defender Real-Time Protection status." `
            -Recommendation "Run check with administrative privileges." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Query Defender Status
# ------------------------------------------------------------

    fncTestMessage "Querying Defender system status..." "info"

    $rtpEnabled = $false

    try {

        $status = Get-MpComputerStatus

        fncTestMessage "Defender status retrieved successfully." "active"

        if ($status.RealTimeProtectionEnabled) {

            $rtpEnabled = $true
        }

    } catch {

        fncTestMessage "Unable to query Defender status." "warning"
        return
    }

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/001/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus" "link"

# ------------------------------------------------------------
# Real-Time Protection Enabled
# ------------------------------------------------------------

    if ($rtpEnabled) {

        fncTestMessage "Defender Real-Time Protection enabled." "proten"

$exploitationText = @"
Microsoft Defender Real-Time Protection is enabled.

This capability continuously monitors files, processes, and system activity
for malicious behaviour.

Real-Time Protection helps detect:

- Malware execution
- Suspicious scripts
- Known malicious binaries
- Behavioural indicators of compromise
"@

$remediationText = @"
No remediation required.

Maintain this security control and ensure Defender protections remain active.

Recommended best practice:

- Enforce Defender configuration via Group Policy
- Monitor Defender health status centrally
- Prevent local administrators from disabling protection
"@

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "RTP_ENABLED")) `
            -Category "Defense Evasion" `
            -Title "Defender Real-Time Protection Enabled" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "Microsoft Defender Real-Time Protection is enabled." `
            -Recommendation "Maintain Defender Real-Time Protection." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Real-Time Protection Disabled
# ------------------------------------------------------------

    fncTestMessage "Defender Real-Time Protection is disabled." "specpriv"

$exploitationText = @"
Microsoft Defender Real-Time Protection is disabled on this system.

Attackers frequently disable endpoint protection before deploying malware
or persistence mechanisms.

Without Real-Time Protection, malicious files and scripts may execute
without immediate detection.

Common attacker behaviour includes:

- Disabling Defender prior to payload execution
- Deploying ransomware or backdoors
- Installing persistence mechanisms
- Evading endpoint detection systems
"@

$remediationText = @"
Immediate remediation recommended.

1) Re-enable Microsoft Defender Real-Time Protection.
2) Investigate why the protection was disabled.
3) Enforce Defender configuration through Group Policy or MDM.
4) Ensure tamper protection is enabled.
5) Monitor systems for security control tampering.

Real-Time Protection should remain enabled on all production endpoints.
"@

    fncSubmitFinding `
        -Id ("DEFENDER-" + (fncShortHashTag "RTP_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "Defender Real-Time Protection Disabled" `
        -Severity "High" `
        -Status "Detected" `
        -Message "Microsoft Defender Real-Time Protection is disabled." `
        -Recommendation "Re-enable Real-Time Protection immediately." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

}

Export-ModuleMember -Function @("fncCheckDefenderRealtimeProtection", "fncGetMappings_DEFENDER_REALTIME_PROTECTION_CHECK")