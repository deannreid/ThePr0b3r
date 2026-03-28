# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0004"; Name = "Privilege Escalation"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0004/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-119"; Name = "Improper Restriction of Operations within the Bounds of a Memory Buffer"; Url = "https://cwe.mitre.org/data/definitions/119.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-7"; Name = "Software, Firmware, and Information Integrity"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_DRIVER_SIGNATURE_ENFORCEMENT { return $script:Mappings }

# ================================================================
# Function: fncCheckDriverSignatureEnforcement
# Purpose : Evaluate kernel driver signature enforcement posture
# ================================================================
function fncCheckDriverSignatureEnforcement {

    fncSafeSectionHeader "Kernel Driver Signature Enforcement Check"
    $Risk = "Safe"
    $RiskReason = "Reads kernel driver signature enforcement configuration without interacting with drivers"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating kernel-mode code integrity enforcement..." "info"
    Write-Host ""

    $testId = "DRIVER-SIGNATURE-ENFORCEMENT"

    $testSigning = $false
    $noIntegrityChecks = $false
    $secureBoot = $null
    $deviceGuard = $null

    # ------------------------------------------------------------
    # Query BCDEdit (Test Signing / Integrity)
    # ------------------------------------------------------------
    try {

        $bcd = bcdedit 2>$null

        if ($bcd -match "testsigning\s+Yes") { $testSigning = $true }
        if ($bcd -match "nointegritychecks\s+Yes") { $noIntegrityChecks = $true }

    }
    catch {}

    # ------------------------------------------------------------
    # Secure Boot Status
    # ------------------------------------------------------------
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop }
    catch { $secureBoot = $null }

    # ------------------------------------------------------------
    # Device Guard / CI State
    # ------------------------------------------------------------
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    }
    catch {}

    Write-Host ""

    if ($testSigning) {
        fncTestMessage "Test Signing Enabled: True" "specpriv"
    }
    else {
        fncTestMessage "Test Signing Enabled: False" "proten"
    }

    if ($noIntegrityChecks) {
        fncTestMessage "Integrity Checks Disabled: True" "specpriv"
    }
    else {
        fncTestMessage "Integrity Checks Disabled: False" "proten"
    }

    if ($secureBoot -eq $true) {
        fncTestMessage "Secure Boot Enabled: True" "proten"
    }
    else {
        fncTestMessage "Secure Boot Enabled: False" "warning"
    }

    if ($deviceGuard) {
        fncTestMessage ("Code Integrity Enforcement Status: {0}" -f $deviceGuard.CodeIntegrityPolicyEnforcementStatus) "info"
    }

    Write-Host ""

    # ------------------------------------------------------------
    # CRITICAL: Integrity Checks Disabled
    # ------------------------------------------------------------
    if ($noIntegrityChecks -eq $true) {

        fncTestMessage "Kernel integrity checks disabled." "specpriv"

        $exploitationText = @"
Integrity checks are disabled via boot configuration.
This allows unsigned or improperly signed kernel drivers to load.
Attackers can deploy malicious drivers to:
- Disable security controls
- Hide processes and files
- Escalate privileges to SYSTEM
- Persist at kernel level
This configuration represents a severe kernel security weakness.
"@

        $remediationText = @"
Re-enable integrity enforcement:

bcdedit /set nointegritychecks off

Ensure Secure Boot is enabled in UEFI firmware.
Reboot system after changes.
Validate driver signature enforcement via:
- msinfo32
- Device Guard status
- Code Integrity logs
"@

        fncSubmitFinding `
            -Id "DRIVER_SIG_NO_INTEGRITY" `
            -Title "Kernel Integrity Checks Disabled" `
            -Category "Application Control" `
            -Severity "Critical" `
            -Status "Misconfigured" `
            -Message "Boot configuration allows unsigned kernel drivers to load." `
            -Recommendation "Re-enable kernel integrity enforcement immediately." `
            -Evidence @("BCDEdit nointegritychecks=Yes") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # HIGH: Test Signing Enabled
    # ------------------------------------------------------------
    if ($testSigning -eq $true) {

        fncTestMessage "System operating in test signing mode." "specpriv"

        $exploitationText = @"
System is operating in Test Signing mode.
This permits loading of test-signed drivers that are not production-signed.
Attackers can deploy malicious test-signed drivers to:
- Achieve kernel execution
- Bypass EDR
- Manipulate kernel objects
This significantly lowers attacker effort for kernel persistence.
"@

        $remediationText = @"
Disable test signing:

bcdedit /set testsigning off

Reboot the system.
Ensure Secure Boot is enabled.
Validate driver signature enforcement after reboot.
"@

        fncSubmitFinding `
            -Id "DRIVER_SIG_TEST_MODE" `
            -Title "Test Signing Mode Enabled" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Weak Enforcement" `
            -Message "System allows test-signed drivers to load." `
            -Recommendation "Disable test signing and enforce production driver signatures." `
            -Evidence @("BCDEdit testsigning=Yes") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Secure Boot Disabled (Medium Risk)
    # ------------------------------------------------------------
    if ($secureBoot -eq $false) {

        fncTestMessage "Secure Boot disabled." "warning"

        $exploitationText = @"
Secure Boot is disabled.
While driver signature enforcement may still be active,
boot chain validation is weakened.
Attackers with physical or firmware-level access could
modify boot configuration to disable integrity enforcement.
"@

        $remediationText = @"
Enable Secure Boot in UEFI firmware.
Ensure:
- UEFI mode enabled
- CSM disabled
- Platform keys installed
Validate Secure Boot status post-change.
"@

        fncSubmitFinding `
            -Id "DRIVER_SIG_SECUREBOOT_DISABLED" `
            -Title "Secure Boot Disabled" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Reduced Boot Integrity" `
            -Message "Secure Boot is not enforcing kernel boot integrity." `
            -Recommendation "Enable Secure Boot to strengthen boot chain validation." `
            -Evidence @("SecureBoot=False") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Healthy State
    # ------------------------------------------------------------
    fncTestMessage "Kernel driver signature enforcement active." "proten"

    $exploitationText = @"
Kernel driver signature enforcement is active.
Integrity checks are enabled.
Test signing is disabled.
Secure Boot is enabled.
This significantly increases attacker difficulty for kernel-level persistence or privilege escalation.
"@

    $remediationText = @"
Maintain current configuration.
Monitor:
- Code Integrity logs
- Unexpected driver loads
- BCDEdit configuration drift
Ensure Secure Boot remains enabled.
"@

    fncSubmitFinding `
        -Id "DRIVER_SIG_ENFORCED" `
        -Title "Driver Signature Enforcement Active" `
        -Category "Application Control" `
        -Severity "Info" `
        -Status "Enforced" `
        -Message "Kernel driver signature enforcement is active and secure." `
        -Recommendation "Maintain enforcement and monitor integrity logs." `
        -Evidence @("SecureBoot=True", "IntegrityChecks=True", "TestSigning=False") `
        -SourceTests @($testId) `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

Export-ModuleMember -Function @("fncCheckDriverSignatureEnforcement", "fncGetMappings_DRIVER_SIGNATURE_ENFORCEMENT")