# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1003"; Name = "OS Credential Dumping"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1003/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-522"; Name = "Insufficiently Protected Credentials"; Url = "https://cwe.mitre.org/data/definitions/522.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6"; Name = "Least Privilege"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "IA-5"; Name = "Authenticator Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_CREDENTIAL_GUARD_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckCredentialGuardStatus
# Purpose : Determine whether Windows Credential Guard is enabled
# Notes   : Uses DeviceGuard CIM provider and SecureBoot checks.
#           Compatible with Windows 10 / Server 2016+ systems.
# ================================================================
function fncCheckCredentialGuardStatus {

    fncSafeSectionHeader "Credential Guard Protection Assessment"

    $Risk = "Medium"
    $RiskReason = "Queries DeviceGuard CIM provider and SecureBoot state which may appear in EDR telemetry"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating Windows Credential Guard and VBS configuration..." "info"
    Write-Host ""

    $testId = "CREDENTIAL-GUARD-CHECK"

    $credGuardEnabled = $false
    $secureBoot = $false
    $vbsEnabled = $false
    $runningStatus = "Unknown"

    $evidence = @()
    $references = @(
        "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
        "https://attack.mitre.org/techniques/T1003/",
        "https://github.com/gentilkiwi/mimikatz",
        "https://github.com/fortra/impacket",
        "https://github.com/helpsystems/nanodump",
        "https://kevin.gtfkd.com/vuln/CVE-2021-33739",
        "https://www.cve.org/CVERecord/SearchResults?query=CVE-2021-33739"
    )

    # ------------------------------------------------------------
    # Base Exploitation / Remediation
    # ------------------------------------------------------------

    $exploitationText = @"
Windows Credential Guard protects authentication secrets by isolating
credential material within a virtualization-based security (VBS)
environment.

If Credential Guard is not enabled, attackers who obtain local
administrator privileges may be able to extract credential material
directly from LSASS memory.

Typical attack chain:

1) Attacker gains local administrator privileges
2) LSASS memory is accessed or dumped
3) Authentication secrets extracted

Potential secrets exposed:

- NTLM password hashes
- Kerberos tickets
- Cached credentials
- Domain authentication tokens

Common tools used:

- Mimikatz
- ProcDump
- nanodump
- Impacket

Credential Guard significantly reduces the success of credential
dumping attacks by isolating secrets from the normal OS environment.
"@

    $remediationText = @"
Enable Credential Guard wherever supported.

Recommended steps:

1) Enable Virtualization Based Security (VBS)
2) Enable Credential Guard via Group Policy

Group Policy Path:

Computer Configuration â†’
Administrative Templates â†’
System â†’
Device Guard â†’
Turn On Virtualization Based Security

Set:

Credential Guard Configuration = Enabled

Hardware prerequisites:

- UEFI firmware
- Secure Boot enabled
- Hardware virtualization extensions
- IOMMU support where available

After enabling:

- Reboot systems
- Verify Credential Guard operational state
- Prioritise administrative workstations
- Monitor credential dumping attempts
"@

    # ------------------------------------------------------------
    # Check Win32_DeviceGuard
    # ------------------------------------------------------------

    try {

        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction Stop

        $evidence += ("DeviceGuardServicesRunning={0}" -f ($dg.SecurityServicesRunning -join ","))

        if ($dg.SecurityServicesRunning) {

            if ($dg.SecurityServicesRunning -contains 1) {
                $credGuardEnabled = $true
            }
        }

        if ($dg.VirtualizationBasedSecurityStatus -eq 2) {

            $vbsEnabled = $true
        }

        $evidence += ("VBSStatus={0}" -f $dg.VirtualizationBasedSecurityStatus)

    }
    catch {

        fncTestMessage "Unable to query Win32_DeviceGuard." "warning"
        $evidence += "DeviceGuardQueryFailed=True"
    }

    # ------------------------------------------------------------
    # Check Secure Boot
    # ------------------------------------------------------------

    try {

        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

        if ($sb -eq $true) {
            $secureBoot = $true
        }

        $evidence += ("SecureBoot={0}" -f $secureBoot)

    }
    catch {

        fncTestMessage "Secure Boot status could not be determined." "warning"
        $evidence += "SecureBootQueryFailed=True"
    }

    # ------------------------------------------------------------
    # Determine running state
    # ------------------------------------------------------------

    if ($credGuardEnabled) {

        $runningStatus = "Enabled"

    }
    elseif ($vbsEnabled) {

        $runningStatus = "VBS Enabled (Credential Guard Not Active)"

    }
    else {

        $runningStatus = "Disabled"
    }

    fncTestMessage ("Credential Guard Status: {0}" -f $runningStatus) "info"

    Write-Host ""

    # ------------------------------------------------------------
    # Credential Guard Enabled
    # ------------------------------------------------------------

    if ($credGuardEnabled) {

        fncTestMessage "Credential Guard is active and protecting credential material." "proten"

        $exploitationText = @"
Credential Guard is enabled on this system.

Credential material is isolated inside a virtualization protected
environment and cannot be directly accessed from LSASS memory.

While attackers may still attempt to obtain:

- Kerberos tickets
- Access tokens
- Application credentials

Credential Guard significantly reduces the success rate of common
credential dumping techniques.
"@

        $remediationText = @"
No remediation required.

Maintain secure configuration:

- Credential Guard remains enabled
- Virtualization Based Security remains active
- Secure Boot remains enabled
- Administrative access remains controlled
- Credential dumping behaviour is monitored
"@

        fncSubmitFinding `
            -Id ("CG-" + (fncShortHashTag "CREDENTIAL_GUARD_ENABLED")) `
            -Title "Credential Guard Enabled" `
            -Category "Credential Protection" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "Credential Guard is enabled and protecting authentication secrets." `
            -Recommendation "Maintain current configuration." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        Write-Host ""
        return
    }

    # ------------------------------------------------------------
    # Credential Guard Disabled
    # ------------------------------------------------------------

    fncTestMessage "Credential Guard is not enabled." "specpriv"

    fncSubmitFinding `
        -Id ("CG-" + (fncShortHashTag "CREDENTIAL_GUARD_DISABLED")) `
        -Title "Credential Guard Not Enabled" `
        -Category "Credential Protection" `
        -Severity "Medium" `
        -Status "Detected" `
        -Message ("Credential Guard not enabled. SecureBoot='{0}' VBS='{1}'." -f $secureBoot, $vbsEnabled) `
        -Recommendation "Enable Credential Guard via Group Policy." `
        -Evidence $evidence `
        -SourceTests @($testId) `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    fncTestMessage "References / Further Reading:" "link"

    foreach ($ref in $references) {
        fncTestMessage $ref "link"
    }
    Write-Host ""

}

Export-ModuleMember -Function @("fncCheckCredentialGuardStatus", "fncGetMappings_CREDENTIAL_GUARD_CHECK")