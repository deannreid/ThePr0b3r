# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1557.001"; Name = "LLMNR/NBT-NS Poisoning"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1557/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-923"; Name = "Improper Restriction of Communication Channel to Intended Endpoints"; Url = "https://cwe.mitre.org/data/definitions/923.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SC-7"; Name = "Boundary Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "18.5.8.1"; Name = "Ensure NetBIOS Name Service is disabled on all network interfaces"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Disabling NetBIOS over TCP/IP removes the NBT-NS poisoning surface used by tools like Responder and Inveigh." }
    )
}

function fncGetMappings_CIS_NETBIOS_CONFIG { return $script:Mappings }

# ================================================================
# Function: fncCheckNetBIOSConfiguration
# Purpose : Evaluate whether NetBIOS over TCP/IP is enabled
# ================================================================
function fncCheckNetBIOSConfiguration {

    fncSafeSectionHeader "NetBIOS over TCP/IP Security Assessment"

    $Risk = "Safe"
    $RiskReason = "Reads adapter configuration via WMI only"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating NetBIOS over TCP/IP configuration across active adapters..." "info"
    Write-Host ""

    $testId = "CIS-NETBIOS-CONFIG"

    $enabledAdapters = @()
    $disabledAdapters = @()
    $defaultAdapters = @()
    $unknownAdapters = @()
    $evidence = @()

    try {

        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPEnabled -eq $true }

        foreach ($adapter in $adapters) {

            $name = $adapter.Description
            $option = $adapter.TcpipNetbiosOptions

            $evidence += ("Adapter={0} NetbiosOption={1}" -f $name,$option)

            switch ($option) {

                0 {
                    fncTestMessage ("NetBIOS default on adapter: {0}" -f $name) "warning"
                    $defaultAdapters += $name
                }

                1 {
                    fncTestMessage ("NetBIOS enabled on adapter: {0}" -f $name) "specpriv"
                    $enabledAdapters += $name
                }

                2 {
                    fncTestMessage ("NetBIOS disabled on adapter: {0}" -f $name) "proten"
                    $disabledAdapters += $name
                }

                default {
                    fncTestMessage ("NetBIOS state unknown on adapter: {0}" -f $name) "warning"
                    $unknownAdapters += $name
                }

            }

        }

    }
    catch {

        fncTestMessage "Failed to enumerate NetBIOS adapter configuration." "warning"
        $unknownAdapters += "EnumerationFailed"

    }

    Write-Host ""

    $netbiosRiskPresent = $false
    if ($enabledAdapters.Count -gt 0) { $netbiosRiskPresent = $true }
    if ($defaultAdapters.Count -gt 0) { $netbiosRiskPresent = $true }
    if ($unknownAdapters.Count -gt 0) { $netbiosRiskPresent = $true }

    if ($netbiosRiskPresent) {

        $issueParts = @()

        if ($enabledAdapters.Count -gt 0) {
            $issueParts += ("Enabled on {0} adapter(s)" -f $enabledAdapters.Count)
            fncTestMessage ("Enabled adapters: {0}" -f ($enabledAdapters -join ", ")) "link"
        }

        if ($defaultAdapters.Count -gt 0) {
            $issueParts += ("Default on {0} adapter(s)" -f $defaultAdapters.Count)
            fncTestMessage ("Default adapters: {0}" -f ($defaultAdapters -join ", ")) "link"
        }

        if ($unknownAdapters.Count -gt 0) {
            $issueParts += ("Unknown on {0} adapter(s)" -f $unknownAdapters.Count)
            fncTestMessage ("Unknown state adapters: {0}" -f ($unknownAdapters -join ", ")) "link"
        }

        $summary = "NetBIOS over TCP/IP enabled or not explicitly disabled on one or more adapters."

        if ($issueParts.Count -gt 0) {
            $summary = "{0} Detail: {1}." -f $summary, ($issueParts -join "; ")
        }

        $exploitationText = @"
NetBIOS over TCP/IP enables legacy name resolution behaviour that attackers can abuse.

Attack path:

Victim attempts hostname resolution ->
System falls back to NetBIOS broadcast ->
Attacker responds claiming to be target host ->
Victim sends NTLM authentication ->
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
"@

        $remediationText = @"
Disable NetBIOS over TCP/IP on all adapters where not required.

Recommended configuration:

Adapter IPv4 â†’
Advanced â†’
WINS â†’
Disable NetBIOS over TCP/IP

Expected hardened value:
TcpipNetbiosOptions = 2

Additional hardening:
- Disable LLMNR
- Enforce SMB signing
- Reduce NTLM usage
"@

        fncSubmitFinding `
            -Id ("NETBIOS-" + (fncShortHashTag "NETBIOS_ENABLED")) `
            -Title "NetBIOS Over TCP/IP Enabled or Not Explicitly Disabled" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message $summary `
            -Recommendation "Disable NetBIOS over TCP/IP on all adapters where not required." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    fncTestMessage "NetBIOS over TCP/IP disabled on all enumerated adapters." "proten"

    fncSubmitFinding `
        -Id ("NETBIOS-" + (fncShortHashTag "NETBIOS_DISABLED")) `
        -Title "NetBIOS Over TCP/IP Disabled" `
        -Category "Network Security" `
        -Severity "Info" `
        -Status "Configured" `
        -Message "NetBIOS over TCP/IP disabled on all active adapters." `
        -Recommendation "No action required." `
        -Evidence $evidence `
        -SourceTests @($testId)

}

Export-ModuleMember -Function @("fncCheckNetBIOSConfiguration", "fncGetMappings_CIS_NETBIOS_CONFIG")