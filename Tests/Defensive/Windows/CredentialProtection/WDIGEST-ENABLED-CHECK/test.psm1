# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1003"; Name = "OS Credential Dumping"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1003/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-312"; Name = "Cleartext Storage of Sensitive Information"; Url = "https://cwe.mitre.org/data/definitions/312.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6"; Name = "Least Privilege"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "IA-5"; Name = "Authenticator Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_WDIGEST_ENABLED_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckWDigestExposure
# Purpose : Detect whether WDigest credential caching is enabled
# Notes   : Checks registry configuration for UseLogonCredential
# ================================================================
function fncCheckWDigestExposure {

    fncPrintSectionHeader "WDigest Credential Exposure Validation"

    $Risk = "Safe"
    $RiskReason = "Performs read-only registry inspection to determine WDigest credential caching configuration"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking WDigest credential caching configuration..." "info"

    # ------------------------------------------------------------
    # Registry Path
    # ------------------------------------------------------------

    $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $regValue = "UseLogonCredential"

    $wdigestEnabled = $false
    $valueDetected  = $null

# ------------------------------------------------------------
# Base Exploitation / Remediation
# ------------------------------------------------------------

$baseExploitation = @"
WDigest is a legacy authentication protocol originally used for HTTP digest authentication.

Older versions of Windows stored user credentials in reversible plaintext form
in the LSASS process to support WDigest authentication.

If WDigest credential caching is enabled, attackers who obtain access to LSASS memory
may retrieve plaintext passwords for logged-in users.

Attack path:

1) Attacker compromises a workstation or server
2) Attacker obtains memory access to LSASS
3) WDigest plaintext credentials are extracted
4) Attacker obtains real user passwords
5) Credentials are reused across the environment

Common tools used:

- Mimikatz
- SafetyKatz
- LSASS dump tools
- Credential harvesting malware

Once plaintext credentials are recovered, attackers can:

- Authenticate directly to domain resources
- Move laterally using SMB / WinRM / RDP
- Escalate privileges
- Compromise domain controllers

Microsoft disabled WDigest credential caching by default starting with
Windows 8.1 and Windows Server 2012 R2.
"@

$baseRemediation = @"
WDigest credential caching should remain disabled unless absolutely required
for legacy compatibility.

Recommended remediation:

1) Ensure the registry key below is absent or set to 0

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
UseLogonCredential = 0

2) Remove any Group Policy or configuration management that enables WDigest.

3) Restart the system after remediation.

4) Monitor registry changes affecting WDigest settings.

5) Implement LSASS protections including:

- Credential Guard
- LSASS Protected Process (RunAsPPL)
- EDR monitoring for credential dumping
"@

# ------------------------------------------------------------
# Read registry value
# ------------------------------------------------------------

try {

    if (Test-Path $regPath) {

        $prop = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue

        if ($null -ne $prop) {

            $valueDetected = $prop.$regValue
            fncTestMessage ("Registry value detected: UseLogonCredential = {0}" -f $valueDetected) "active"

            if ($valueDetected -eq 1) {
                $wdigestEnabled = $true
            }
        }
        else {
            fncTestMessage "WDigest registry value not present (secure default)." "proten"
        }
    }
    else {
        fncTestMessage "WDigest registry path not present." "proten"
    }

} catch {

    fncTestMessage "Failed to read WDigest configuration." "warning"
}

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

fncTestMessage "https://attack.mitre.org/techniques/T1003/001/" "link"
fncTestMessage "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-allow-digest-authentication" "link"

# ------------------------------------------------------------
# WDigest Disabled
# ------------------------------------------------------------

if (-not $wdigestEnabled) {

    fncTestMessage "WDigest credential caching is disabled." "proten"

$exploitationText = @"
WDigest credential caching is disabled on this system.

This reduces the likelihood that plaintext credentials will be stored
in LSASS memory.

Attackers who dump LSASS memory will still obtain:

- NTLM hashes
- Kerberos tickets
- Security tokens

However, plaintext passwords are less likely to be exposed.

Disabling WDigest significantly reduces the impact of LSASS credential dumping attacks.
"@

$remediationText = @"
No remediation required.

Maintain the current secure configuration by ensuring:

- WDigest remains disabled
- Credential Guard or LSASS protection is enabled where possible
- Administrative logons are restricted to hardened systems
- Monitoring exists for credential dumping behaviour
"@

    fncSubmitFinding `
        -Id ("WDIGEST-" + (fncShortHashTag "WDIGEST_DISABLED")) `
        -Category "Credential Protection" `
        -Title "WDigest Credential Caching Disabled" `
        -Severity "Info" `
        -Status "Protected" `
        -Message "WDigest credential caching is disabled." `
        -Recommendation "Maintain current secure configuration." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    return
}

# ------------------------------------------------------------
# WDigest Enabled
# ------------------------------------------------------------

fncTestMessage "WDigest credential caching is ENABLED." "specpriv"

$exploitationText = @"
WDigest credential caching is enabled on this system.

This configuration allows LSASS to store user credentials in plaintext memory
to support legacy authentication workflows.

If attackers gain access to LSASS memory, they may recover plaintext passwords
for users currently logged into the system.

Attack workflow:

1) Attacker compromises the system
2) Attacker obtains access to LSASS memory
3) Credential dumping tools extract plaintext passwords
4) Passwords are reused across the environment

Privileged logons dramatically increase the impact because administrator
or service account passwords may be exposed.
"@

$remediationText = @"
Immediate remediation recommended.

1) Disable WDigest credential caching.

Set the registry value:

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
UseLogonCredential = 0

2) Restart the system after applying the change.

3) Review Group Policy configuration to ensure WDigest is not re-enabled.

4) Enable LSASS protection mechanisms:

- Credential Guard
- RunAsPPL
- EDR detection of credential dumping
"@

fncSubmitFinding `
    -Id ("WDIGEST-" + (fncShortHashTag "WDIGEST_ENABLED")) `
    -Category "Credential Protection" `
    -Title "WDigest Credential Caching Enabled" `
    -Severity "High" `
    -Status "Detected" `
    -Message "WDigest credential caching is enabled and may expose plaintext credentials in LSASS." `
    -Recommendation "Disable WDigest credential caching and restart the system." `
    -Exploitation $exploitationText `
    -Remediation $remediationText

}

Export-ModuleMember -Function @("fncCheckWDigestExposure", "fncGetMappings_WDIGEST_ENABLED_CHECK")