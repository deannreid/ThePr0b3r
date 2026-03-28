# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1003"; Name = "OS Credential Dumping"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1003/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6"; Name = "Least Privilege"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "IA-5"; Name = "Authenticator Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_LSASS_PROTECTION_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckLSASSProtectedProcess
# Purpose : Determine whether LSASS is running as a Protected Process (RunAsPPL)
# Notes   : Checks registry configuration and runtime LSASS protection state
# ================================================================
function fncCheckLSASSProtectedProcess {

    fncPrintSectionHeader "LSASS Protected Process Validation"

    $Risk = "Low"
    $RiskReason = "Performs read-only registry inspection and process enumeration to determine LSASS protection status"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking LSASS Protected Process (RunAsPPL) configuration..." "info"

    $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $regValue = "RunAsPPL"

    $pplEnabled = $false
    $pplValue   = $null

# ------------------------------------------------------------
# Base Exploitation / Remediation
# ------------------------------------------------------------

$baseExploitation = @"
LSASS (Local Security Authority Subsystem Service) is responsible for storing
authentication material used by Windows systems.

This includes:

- NTLM password hashes
- Kerberos tickets
- Cached credentials
- Authentication tokens

If LSASS is not running as a Protected Process (RunAsPPL), attackers with
administrative privileges can access LSASS memory and extract credentials.

Attack path:

1) Attacker gains administrative privileges on a host
2) Attacker obtains access to LSASS memory
3) Credential dumping tools extract authentication material
4) Attacker reuses credentials to authenticate across the environment
5) Lateral movement and privilege escalation follow

Common tools used:

- Mimikatz
- ProcDump
- Task Manager memory dump
- Credential harvesting malware

LSASS Protected Process (PPL) restricts access to LSASS memory so that only
trusted signed code can interact with it.

Without PPL enabled, credential dumping becomes significantly easier and
is commonly used during post-exploitation.
"@

$baseRemediation = @"
LSASS should run as a Protected Process wherever possible.

Recommended remediation:

1) Enable LSASS Protected Process via registry or Group Policy.

Registry location:

HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL = 1

2) Restart the system after applying the configuration.

3) Ensure systems support the required protections such as:

- Secure Boot
- Modern Windows versions
- Trusted drivers

4) Pair LSASS protection with additional controls:

- Credential Guard
- Endpoint detection for credential dumping
- Restricted administrator logons

Operational best practice:

- Enable RunAsPPL across domain-joined systems
- Prioritise administrative workstations
- Monitor for attempts to access LSASS memory
"@

# ------------------------------------------------------------
# Check Registry
# ------------------------------------------------------------

try {

    if (Test-Path $regPath) {

        $prop = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue

        if ($null -ne $prop) {

            $pplValue = $prop.$regValue
            fncTestMessage ("Registry value detected: RunAsPPL = {0}" -f $pplValue) "active"

            if ($pplValue -eq 1 -or $pplValue -eq 2) {

                $pplEnabled = $true
            }
        }
        else {

            fncTestMessage "RunAsPPL registry value not present." "warning"
        }
    }

} catch {

    fncTestMessage "Unable to read LSASS protection configuration." "warning"
}

# ------------------------------------------------------------
# Check LSASS Process State
# ------------------------------------------------------------

$lsassRunning = $false

try {

    $proc = Get-Process -Name lsass -ErrorAction Stop

    if ($proc) {
        $lsassRunning = $true
        fncTestMessage "LSASS process is running." "active"
    }

} catch {

    fncTestMessage "Unable to query LSASS process." "warning"
}

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

fncTestMessage "https://attack.mitre.org/techniques/T1003/001/" "link"
fncTestMessage "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection" "link"

# ------------------------------------------------------------
# LSASS Protected
# ------------------------------------------------------------

if ($pplEnabled) {

    fncTestMessage "LSASS Protected Process (RunAsPPL) is enabled." "proten"

$exploitationText = @"
LSASS is configured to run as a Protected Process (PPL).

This protection restricts access to LSASS memory so that only trusted
signed processes can interact with the authentication subsystem.

This significantly reduces the effectiveness of many credential dumping
techniques commonly used by attackers.

While credential theft techniques may still attempt to target other
sources such as:

- Browser credential stores
- Kerberos tickets
- Application secrets

RunAsPPL makes traditional LSASS memory dumping far more difficult.
"@

$remediationText = @"
No remediation required.

Maintain the secure configuration by ensuring:

- LSASS continues running as a Protected Process
- Credential Guard remains enabled where supported
- Monitoring exists for credential dumping behaviour
- Administrative access is tightly controlled
"@

    fncSubmitFinding `
        -Id ("LSASS-" + (fncShortHashTag "PPL_ENABLED")) `
        -Category "Credential Protection" `
        -Title "LSASS Protected Process Enabled" `
        -Severity "Info" `
        -Status "Protected" `
        -Message "LSASS is running with Protected Process Light (RunAsPPL)." `
        -Recommendation "Maintain current secure configuration." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    return
}

# ------------------------------------------------------------
# LSASS Not Protected
# ------------------------------------------------------------

fncTestMessage "LSASS Protected Process (RunAsPPL) is not enabled." "specpriv"

$exploitationText = @"
LSASS is not running as a Protected Process.

This means processes running with administrative privileges may access
LSASS memory and extract credential material.

Attackers frequently exploit this condition during post-exploitation
to harvest credentials from compromised hosts.

Credential dumping tools may retrieve:

- NTLM password hashes
- Kerberos tickets
- Cached credentials
- Authentication tokens

Once credentials are extracted, attackers may:

- Authenticate to additional systems
- Move laterally across the network
- Escalate privileges
- Target domain infrastructure

If administrators log onto the affected system, credential theft may
lead directly to high privilege compromise.
"@

$remediationText = @"
Enable LSASS Protected Process (RunAsPPL) to reduce credential theft risk.

Recommended actions:

1) Set the registry value:

HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL = 1

2) Restart the system after applying the configuration.

3) Verify that LSASS starts as a protected process.

4) Ensure systems support required protections including Secure Boot.

5) Deploy LSASS protection across domain-joined systems, prioritising
administrative workstations and privileged servers.
"@

fncSubmitFinding `
    -Id ("LSASS-" + (fncShortHashTag "PPL_DISABLED")) `
    -Category "Credential Protection" `
    -Title "LSASS Protected Process Not Enabled" `
    -Severity "Medium" `
    -Status "Detected" `
    -Message ("LSASS Protected Process not enabled. RegistryValue='{0}'." -f $pplValue) `
    -Recommendation "Enable RunAsPPL to protect LSASS memory." `
    -Exploitation $exploitationText `
    -Remediation $remediationText

}

Export-ModuleMember -Function @("fncCheckLSASSProtectedProcess", "fncGetMappings_LSASS_PROTECTION_CHECK")