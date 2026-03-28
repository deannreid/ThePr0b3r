# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1021.002"; Name = "Remote Services: SMB/Windows Admin Shares"; Tactic = "Lateral Movement"; Url = "https://attack.mitre.org/techniques/T1021/002/" }
        [pscustomobject]@{ Id = "T1557"; Name = "Adversary-in-the-Middle"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1557/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-311"; Name = "Missing Encryption of Sensitive Data"; Url = "https://cwe.mitre.org/data/definitions/311.html" }
        [pscustomobject]@{ Id = "CWE-287"; Name = "Improper Authentication"; Url = "https://cwe.mitre.org/data/definitions/287.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SC-8"; Name = "Transmission Confidentiality and Integrity"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SC-13"; Name = "Cryptographic Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AC-17"; Name = "Remote Access"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "2.3.7.1"; Name = "Microsoft network client: Digitally sign communications (always)"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Require SMB client signing to prevent relay and man-in-the-middle attacks against SMB sessions." }
        [pscustomobject]@{ Id = "2.3.7.3"; Name = "Microsoft network server: Digitally sign communications (always)"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Require SMB server signing to prevent session hijacking and relay attacks." }
        [pscustomobject]@{ Id = "18.3.2"; Name = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Disable the SMBv1 server to eliminate EternalBlue and related legacy SMB exploitation." }
        [pscustomobject]@{ Id = "18.3.3"; Name = "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Disable the SMBv1 client driver to remove client-side legacy SMB attack surface." }
    )
}

function fncGetMappings_CIS_SMB_CONFIG { return $script:Mappings }

# ================================================================
# Function: fncCheckSMBConfiguration
# Purpose : Validate SMB security configuration including SMBv1
#           usage and SMB signing enforcement posture
# ================================================================
function fncCheckSMBConfiguration {

    fncSafeSectionHeader "SMB Security Configuration Assessment"

    $Risk = "Low"
    $RiskReason = "Queries SMB configuration and active SMB dialects which may appear in endpoint telemetry"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating SMB protocol usage and signing enforcement posture..." "info"
    Write-Host ""

    $testId = "CIS-SMB-CONFIG"

    $smb1Detected = $false
    $serverSigningRequired = $null
    $clientSigningRequired = $null
    $evidence = @()

    # ==========================================================
    # SMBv1 Detection
    # ==========================================================

    fncTestMessage "Inspecting active SMB dialects..." "info"

    try {

        if (Get-Command Get-SmbConnection -ErrorAction SilentlyContinue) {

            $connections = Get-SmbConnection -ErrorAction SilentlyContinue

            foreach ($c in $connections) {

                if ($c.Dialect -like "1.*") {

                    $smb1Detected = $true
                    $evidence += ("SMB1DialectDetected={0}" -f $c.Dialect)

                }

            }

        }
        else {
            fncTestMessage "Get-SmbConnection cmdlet unavailable." "warning"
        }

    }
    catch {
        fncTestMessage "Unable to inspect SMB dialect usage." "warning"
    }

    if ($smb1Detected) {

        fncTestMessage "SMBv1 protocol detected in active SMB connections." "specpriv"

        $exploitationText = @"
SMBv1 is a deprecated protocol containing multiple critical remote code execution vulnerabilities.

Attack path:
Attacker scans network â†’
SMBv1 detected â†’
Exploit frameworks leverage vulnerabilities such as EternalBlue â†’
Remote SYSTEM level execution.

Common exploitation tooling:
- Metasploit
- Impacket
- Nmap NSE smb-vuln scripts
"@

        $remediationText = @"
Disable SMBv1 across all systems.

Recommended actions:
- Remove SMBv1 Windows feature
- Enforce via Group Policy
- Disable using PowerShell:

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
"@

        fncSubmitFinding `
            -Id ("SMB-" + (fncShortHashTag "SMB1_DETECTED")) `
            -Title "SMBv1 Protocol Usage Detected" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message "SMBv1 protocol observed in active SMB dialects." `
            -Recommendation "Disable SMBv1 across the environment." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

    }
    else {

        fncTestMessage "No SMBv1 dialects observed in active connections." "proten"

    }

    Write-Host ""

    # ==========================================================
    # SMB Server Signing
    # ==========================================================

    fncTestMessage "Inspecting SMB server signing configuration..." "info"

    try {

        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {

            $cfg = Get-SmbServerConfiguration
            $serverSigningRequired = $cfg.RequireSecuritySignature
            $evidence += ("ServerRequireSigning={0}" -f $serverSigningRequired)

        }
        else {
            fncTestMessage "Get-SmbServerConfiguration cmdlet unavailable." "warning"
        }

    }
    catch {
        fncTestMessage "Unable to query SMB server configuration." "warning"
    }

    if ($serverSigningRequired -eq $false) {

        fncTestMessage "SMB server signing NOT enforced." "specpriv"

        $exploitationText = @"
If SMB signing is not required attackers can perform NTLM relay attacks.

Attack path:
Victim authenticates to attacker â†’
NTLM authentication captured â†’
ntlmrelayx relays authentication to SMB or LDAP â†’
Attacker gains access using victim credentials.

Potential outcomes:
- Privilege escalation
- Domain compromise
- Administrative access to servers
"@

        $remediationText = @"
Require SMB signing on all servers.

Group Policy:
Microsoft network server: Digitally sign communications (always)

Registry equivalent:
RequireSecuritySignature = 1
"@

        fncSubmitFinding `
            -Id ("SMB-" + (fncShortHashTag "SERVER_SIGNING_DISABLED")) `
            -Title "SMB Server Signing Not Enforced" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message "SMB server does not require message signing." `
            -Recommendation "Enable SMB signing enforcement." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

    }
    else {

        fncTestMessage "SMB server signing enforced." "proten"

    }

    Write-Host ""

    # ==========================================================
    # SMB Client Signing
    # ==========================================================

    fncTestMessage "Inspecting SMB client signing configuration..." "info"

    try {

        if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {

            $cfg = Get-SmbClientConfiguration
            $clientSigningRequired = $cfg.RequireSecuritySignature
            $evidence += ("ClientRequireSigning={0}" -f $clientSigningRequired)

        }
        else {
            fncTestMessage "Get-SmbClientConfiguration cmdlet unavailable." "warning"
        }

    }
    catch {
        fncTestMessage "Unable to query SMB client configuration." "warning"
    }

    if ($clientSigningRequired -eq $false) {

        fncTestMessage "SMB client signing NOT enforced." "warning"

        $exploitationText = @"
When SMB client signing is not required attackers can intercept
authentication attempts and relay them to other SMB services.

Attack path:
Victim initiates SMB authentication â†’
Attacker intercepts NTLM handshake â†’
Authentication relayed to another system â†’
Attacker gains authenticated access.

Commonly combined with:
- LLMNR poisoning
- NetBIOS poisoning
- NTLM relay attacks
"@

        $remediationText = @"
Enable SMB signing on SMB clients.

Group Policy:
Microsoft network client: Digitally sign communications (always)

Ensure both client and server enforce signing.
"@

        fncSubmitFinding `
            -Id ("SMB-" + (fncShortHashTag "CLIENT_SIGNING_DISABLED")) `
            -Title "SMB Client Signing Not Enforced" `
            -Category "Network Security" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "SMB client does not require message signing." `
            -Recommendation "Enable SMB signing enforcement." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

    }
    else {

        fncTestMessage "SMB client signing enforced." "proten"

    }

}

Export-ModuleMember -Function @("fncCheckSMBConfiguration", "fncGetMappings_CIS_SMB_CONFIG")