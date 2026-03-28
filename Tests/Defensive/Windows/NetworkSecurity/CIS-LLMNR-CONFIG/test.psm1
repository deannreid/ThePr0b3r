# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1557"; Name = "Adversary-in-the-Middle"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1557/" }
        [pscustomobject]@{ Id = "T1187"; Name = "Forced Authentication"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1187/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-300"; Name = "Channel Accessible by Non-Endpoint"; Url = "https://cwe.mitre.org/data/definitions/300.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SC-8"; Name = "Transmission Confidentiality and Integrity"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "18.5.4.2"; Name = "Ensure 'Turn off Multicast Name Resolution' is set to 'Enabled'"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Disabling LLMNR eliminates the multicast name resolution vector exploited by tools like Responder to capture NTLMv2 hashes." }
    )
}

function fncGetMappings_CIS_LLMNR_CONFIG { return $script:Mappings }

# ================================================================
# Function: fncCheckLLMNRConfiguration
# Purpose : Evaluate whether LLMNR is enabled on the host
# ================================================================
function fncCheckLLMNRConfiguration {

    fncSafeSectionHeader "LLMNR Configuration Assessment"

    $Risk = "Safe"
    $RiskReason = "Reads DNS Client policy registry keys only"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating multicast name resolution configuration..." "info"
    Write-Host ""

    $testId = "CIS-LLMNR-CONFIG"

    $llmnrState = "Unknown"
    $llmnrEnabled = $false
    $detail = ""
    $evidence = @()

    try {

        $reg = Get-ItemProperty `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
            -Name "EnableMulticast" `
            -ErrorAction SilentlyContinue

        if ($null -eq $reg) {

            $llmnrState = "NotConfigured"
            $llmnrEnabled = $true
            $detail = "Policy key missing; LLMNR not explicitly disabled."
            $evidence += "EnableMulticast=NotConfigured"

        }
        elseif ($reg.EnableMulticast -eq 0) {

            $llmnrState = "Disabled"
            $llmnrEnabled = $false
            $detail = "EnableMulticast=0"
            $evidence += "EnableMulticast=0"

        }
        elseif ($reg.EnableMulticast -eq 1) {

            $llmnrState = "Enabled"
            $llmnrEnabled = $true
            $detail = "EnableMulticast=1"
            $evidence += "EnableMulticast=1"

        }
        else {

            $llmnrState = "Unexpected"
            $llmnrEnabled = $true
            $detail = ("Unexpected EnableMulticast value: {0}" -f $reg.EnableMulticast)
            $evidence += ("EnableMulticastUnexpected={0}" -f $reg.EnableMulticast)

        }

    }
    catch {

        $llmnrState = "Unknown"
        $llmnrEnabled = $true
        $detail = "Registry query failed; configuration unknown."
        $evidence += "RegistryReadFailed=True"

    }

    if ($llmnrEnabled) {

        if ($llmnrState -eq "Enabled") {
            fncTestMessage "LLMNR is enabled." "specpriv"
        }
        elseif ($llmnrState -eq "NotConfigured") {
            fncTestMessage "LLMNR not explicitly disabled." "warning"
        }
        else {
            fncTestMessage "LLMNR state uncertain or not hardened." "warning"
        }

        fncTestMessage ("Detail: {0}" -f $detail) "link"

        $exploitationText = @"
LLMNR allows Windows hosts to perform multicast name resolution when DNS fails.

Attack path:

Victim attempts to resolve hostname ->
DNS lookup fails ->
System sends LLMNR multicast query ->
Attacker responds claiming ownership ->
Victim authenticates via NTLM ->
Attacker captures or relays credentials.

Common tooling:
Responder
Inveigh
ntlmrelayx

Potential outcomes:
- NTLM hash capture
- NTLM relay attacks
- Lateral movement
- Privilege escalation
- Domain compromise
"@

        $remediationText = @"
Disable LLMNR via Group Policy.

Computer Configuration â†’
Administrative Templates â†’
Network â†’
DNS Client â†’
Turn Off Multicast Name Resolution = Enabled

Expected hardened value:

EnableMulticast = 0

Additional hardening:
- Disable NetBIOS
- Enforce SMB signing
- Reduce NTLM usage
- Monitor for poisoning activity
"@

        fncSubmitFinding `
            -Id ("LLMNR-" + (fncShortHashTag "LLMNR_ENABLED")) `
            -Title "LLMNR Enabled or Not Explicitly Disabled" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("LLMNR enabled or not hardened. Detail: {0}" -f $detail) `
            -Recommendation "Disable LLMNR via Group Policy." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    fncTestMessage "LLMNR explicitly disabled." "proten"
    fncTestMessage ("Detail: {0}" -f $detail) "link"

    fncSubmitFinding `
        -Id ("LLMNR-" + (fncShortHashTag "LLMNR_DISABLED")) `
        -Title "LLMNR Disabled" `
        -Category "Network Security" `
        -Severity "Info" `
        -Status "Configured" `
        -Message "LLMNR explicitly disabled via policy." `
        -Recommendation "No action required." `
        -Evidence $evidence `
        -SourceTests @($testId)

}

Export-ModuleMember -Function @("fncCheckLLMNRConfiguration", "fncGetMappings_CIS_LLMNR_CONFIG")