# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0002"; Name = "Execution"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0002/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Restriction of Operations"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-7"; Name = "Least Functionality"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_SMARTSCREEN_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckSmartScreen
# Purpose : Evaluate Microsoft Defender SmartScreen enforcement
# ================================================================
function fncCheckSmartScreen {
    fncSafeSectionHeader "Microsoft Defender SmartScreen Check"
    $Risk = "Safe"
    $RiskReason = "Reads SmartScreen configuration from registry without interacting with SmartScreen services"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating SmartScreen policy and enforcement state..." "info"
    Write-Host ""

    $testId = "SMARTSCREEN-CHECK"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

    $enabled = $null
    $policyEnforced = $false
    $policyValue = $null
    $localValue = $null

    # ------------------------------------------------------------
    # Check Policy Key
    # ------------------------------------------------------------
    if (Test-Path $policyPath) {
        try {
            $policy = Get-ItemProperty -Path $policyPath -ErrorAction Stop
            $policyValue = $policy.EnableSmartScreen

            if ($policy.EnableSmartScreen -eq 1) {
                $enabled = $true
                $policyEnforced = $true
            }
            elseif ($policy.EnableSmartScreen -eq 0) {
                $enabled = $false
                $policyEnforced = $true
            }
        }
        catch {}
    }

    # ------------------------------------------------------------
    # Fallback to local config
    # ------------------------------------------------------------
    if ($enabled -eq $null -and (Test-Path $regPath)) {
        try {
            $local = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $localValue = $local.SmartScreenEnabled

            if ($local.SmartScreenEnabled -eq "RequireAdmin" -or
                $local.SmartScreenEnabled -eq "Warn") {
                $enabled = $true
            }
            elseif ($local.SmartScreenEnabled -eq "Off") {
                $enabled = $false
            }
        }
        catch {}
    }

    # ------------------------------------------------------------
    # Enabled State
    # ------------------------------------------------------------
    if ($enabled -eq $true) {

        fncTestMessage "SmartScreen is enabled." "proten"

        if ($policyEnforced) {
            fncTestMessage "SmartScreen enforced via Group Policy." "proten"
        }
        else {
            fncTestMessage "SmartScreen enabled locally (not enforced via GPO)." "warning"
        }

        $exploitationText = @"
SmartScreen provides reputation-based protection for downloaded or low-prevalence applications.

When enabled, Windows evaluates application reputation and blocks or warns before executing
unknown or potentially malicious binaries.

This significantly reduces the success rate of:
- phishing-delivered payloads
- commodity malware loaders
- user-driven malware installation

Attackers must rely on alternative execution paths or user bypass.
"@

        $remediationText = @"
Maintain SmartScreen enforcement via Group Policy.

Recommended configuration:

Computer Configuration â†’
Administrative Templates â†’
Windows Components â†’
File Explorer â†’
Configure Windows Defender SmartScreen = Enabled

Where possible use:
"Require administrator approval before running unknown apps"

Monitor SmartScreen operational logs and Defender alerts.
"@

        fncSubmitFinding `
            -Id ("SMARTSCREEN-" + (fncShortHashTag "ENABLED")) `
            -Title "Microsoft Defender SmartScreen Enabled" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Configured" `
            -Message "SmartScreen reputation-based execution protection is enabled." `
            -Recommendation "Maintain SmartScreen enforcement and monitor SmartScreen events." `
            -Evidence @(
            ("Policy EnableSmartScreen={0}" -f $policyValue),
            ("Local SmartScreenEnabled={0}" -f $localValue),
            ("PolicyEnforced={0}" -f $policyEnforced)
        ) `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Disabled State
    # ------------------------------------------------------------
    if ($enabled -eq $false) {

        fncTestMessage "SmartScreen is disabled." "warning"

        if ($policyEnforced) {
            fncTestMessage "Disabled via Group Policy." "warning"
        }
        else {
            fncTestMessage "Disabled locally." "warning"
        }

        $exploitationText = @"
With SmartScreen disabled, Windows does not perform reputation checks
for downloaded or low-prevalence executables.

This increases the likelihood of successful initial execution for:

- phishing-delivered payloads
- commodity malware installers
- user-executed malicious attachments

Attackers benefit because reputation filtering and warning prompts are removed.
"@

        $remediationText = @"
Enable SmartScreen via Group Policy:

Computer Configuration â†’
Administrative Templates â†’
Windows Components â†’
File Explorer â†’
Configure Windows Defender SmartScreen = Enabled

For stronger protection configure:
"Require administrator approval before running unknown apps"

Also ensure SmartScreen integration remains enabled in supported browsers.
"@

        fncSubmitFinding `
            -Id ("SMARTSCREEN-" + (fncShortHashTag "DISABLED")) `
            -Title "Microsoft Defender SmartScreen Disabled" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Not Enforced" `
            -Message "SmartScreen reputation protection is disabled." `
            -Recommendation "Enable SmartScreen via Group Policy." `
            -Evidence @(
            ("Policy EnableSmartScreen={0}" -f $policyValue),
            ("Local SmartScreenEnabled={0}" -f $localValue),
            ("PolicyEnforced={0}" -f $policyEnforced)
        ) `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Unknown State
    # ------------------------------------------------------------
    fncTestMessage "Unable to determine SmartScreen configuration state." "warning"

    $exploitationText = @"
If SmartScreen configuration cannot be reliably determined,
the system may not be consistently protected by reputation-based execution controls.

Registry drift, incomplete policy application, or configuration errors
can leave systems exposed to low-reputation malware execution.
"@

    $remediationText = @"
Validate SmartScreen configuration using:

- Group Policy Resultant Set of Policy (gpresult /h)
- Windows Security settings
- Defender administrative templates

Ensure explicit SmartScreen enforcement is defined via Group Policy.
"@

    fncSubmitFinding `
        -Id ("SMARTSCREEN-" + (fncShortHashTag "UNKNOWN")) `
        -Title "Microsoft Defender SmartScreen Configuration Uncertain" `
        -Category "Application Control" `
        -Severity "Low" `
        -Status "Unknown" `
        -Message "SmartScreen registry values present but enforcement state could not be reliably determined." `
        -Recommendation "Validate SmartScreen configuration and enforce via Group Policy." `
        -Evidence @(
        ("Policy EnableSmartScreen={0}" -f $policyValue),
        ("Local SmartScreenEnabled={0}" -f $localValue)
    ) `
        -SourceTests @($testId) `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

Export-ModuleMember -Function @("fncCheckSmartScreen", "fncGetMappings_SMARTSCREEN_CHECK")