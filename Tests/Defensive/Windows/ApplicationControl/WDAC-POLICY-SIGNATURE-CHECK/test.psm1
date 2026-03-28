# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0005"; Name = "Defense Evasion"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0005/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Restriction of Operations"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-7"; Name = "Software, Firmware, and Information Integrity"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_WDAC_POLICY_SIGNATURE_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckWDACPolicy
# Purpose : Assess WDAC coverage including multiple policies,
#           supplemental policies, CSP/AppControl deployment,
#           kernel vs UMCI posture, and bypass risk signals
# Notes   : Uses fncTestMessage + fncSubmitFinding
# ================================================================
function fncCheckWDACPolicy {

    fncSafeSectionHeader "WDAC Deep Policy Assessment"
    
    $Risk = "Medium"
    $RiskReason = "Enumerates DeviceGuard state, Code Integrity policies, and CSP registry locations which may appear in EDR telemetry"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating WDAC base policies, supplemental policies, CSP deployment, enforcement state, and bypass risk signals..." "info"
    Write-Host ""

    $testId = "WDAC-POLICY-SIGNATURE-CHECK"

    $ciRoot = "C:\Windows\System32\CodeIntegrity"
    $ciPoliciesDir = Join-Path $ciRoot "CiPolicies\Active"
    $legacyPolicy = Join-Path $ciRoot "CIPolicy.bin"

    $policyFiles = @()
    $supplementalCandidates = @()
    $unsignedPolicies = @()
    $policyEvidence = @()

    $deviceGuard = $null
    $ciStatus = $null
    $umciStatus = $null
    $kernelEnforced = $false
    $kernelAudit = $false
    $umciEnforced = $false
    $umciAudit = $false

    $cspSignals = @()
    $cspPresent = $false

    $bypassSignals = @()
    $bypassRisk = $false

    # ------------------------------------------------------------
    # Helper: safely add evidence
    # ------------------------------------------------------------
    function fncAddEvidenceLine {
        param([string]$Text)
        if (-not [string]::IsNullOrWhiteSpace($Text)) {
            $script:policyEvidence += $Text
        }
    }

    # ------------------------------------------------------------
    # Helper: read Authenticode status
    # ------------------------------------------------------------
    function fncGetWdacSignatureInfo {
        param([string]$Path)

        try {
            $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
            return [PSCustomObject]@{
                Status   = [string]$sig.Status
                Signer   = $(try { [string]$sig.SignerCertificate.Subject } catch { "" })
                NotAfter = $(try { [string]$sig.SignerCertificate.NotAfter } catch { $null })
            }
        }
        catch {
            return [PSCustomObject]@{
                Status   = "Unknown"
                Signer   = ""
                NotAfter = $null
            }
        }
    }

    # ------------------------------------------------------------
    # Helper: crude supplemental policy heuristic
    # ------------------------------------------------------------
    function fncTestLikelySupplementalPolicy {
        param([System.IO.FileInfo]$File)

        $name = $File.Name.ToLowerInvariant()

        if ($name -match "supp" -or
            $name -match "supplement" -or
            $name -match "base_" -or
            $name -match "_base" -or
            $name -match "{.+}") {
            return $true
        }

        return $false
    }

    # ------------------------------------------------------------
    # Enumerate WDAC policy files
    # ------------------------------------------------------------
    fncTestMessage "Inspecting WDAC policy file locations..." "info"

    if (Test-Path -LiteralPath $legacyPolicy -PathType Leaf -ErrorAction SilentlyContinue) {
        try {
            $policyFiles += Get-Item -LiteralPath $legacyPolicy -ErrorAction Stop
        }
        catch {}
    }

    if (Test-Path -LiteralPath $ciPoliciesDir -ErrorAction SilentlyContinue) {
        try {
            $policyFiles += Get-ChildItem -LiteralPath $ciPoliciesDir -File -ErrorAction Stop
        }
        catch {
            fncTestMessage "Unable to enumerate CiPolicies\Active." "warning"
        }
    }

    if (-not $policyFiles -or $policyFiles.Count -eq 0) {
        fncTestMessage "No WDAC policy files detected." "warning"
    }
    else {
        fncTestMessage ("Detected {0} WDAC policy file(s)." -f $policyFiles.Count) "active"
    }

    foreach ($pf in $policyFiles) {

        $sigInfo = fncGetWdacSignatureInfo -Path $pf.FullName
        $isSupplemental = fncTestLikelySupplementalPolicy -File $pf

        if ($isSupplemental) {
            $supplementalCandidates += $pf
        }

        if ($sigInfo.Status -ne "Valid") {
            $unsignedPolicies += $pf
        }

        fncTestMessage ("Policy File: {0}" -f $pf.FullName) "active"

        if ($sigInfo.Status -eq "Valid") {
            fncTestMessage ("Signature Status: {0}" -f $sigInfo.Status) "proten"
        }
        else {
            fncTestMessage ("Signature Status: {0}" -f $sigInfo.Status) "warning"
        }

        if ($isSupplemental) {
            fncTestMessage "Likely supplemental policy candidate detected." "active"
        }

        fncAddEvidenceLine ("PolicyFile={0}" -f $pf.FullName)
        fncAddEvidenceLine ("PolicySignature[{0}]={1}" -f $pf.Name, $sigInfo.Status)
        if ($isSupplemental) {
            fncAddEvidenceLine ("SupplementalCandidate={0}" -f $pf.Name)
        }
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Query Device Guard / WDAC state
    # ------------------------------------------------------------
    fncTestMessage "Querying Device Guard / Code Integrity enforcement state..." "info"

    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

        $ciStatus = $deviceGuard.CodeIntegrityPolicyEnforcementStatus
        $umciStatus = $deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus

        fncTestMessage ("Kernel Code Integrity Status: {0}" -f $ciStatus) "info"
        fncTestMessage ("User Mode Code Integrity Status: {0}" -f $umciStatus) "info"

        if ($ciStatus -eq 2) { $kernelEnforced = $true }
        elseif ($ciStatus -eq 1) { $kernelAudit = $true }

        if ($umciStatus -eq 2) { $umciEnforced = $true }
        elseif ($umciStatus -eq 1) { $umciAudit = $true }

        if ($kernelEnforced) {
            fncTestMessage "Kernel-mode WDAC enforcement is active." "proten"
        }
        elseif ($kernelAudit) {
            fncTestMessage "Kernel-mode WDAC is in audit-only mode." "warning"
        }
        else {
            fncTestMessage "Kernel-mode WDAC enforcement not confirmed." "warning"
        }

        if ($umciEnforced) {
            fncTestMessage "User-mode code integrity enforcement is active." "proten"
        }
        elseif ($umciAudit) {
            fncTestMessage "User-mode code integrity is in audit-only mode." "warning"
        }
        else {
            fncTestMessage "User-mode code integrity enforcement not confirmed." "warning"
        }

        fncAddEvidenceLine ("KernelCIStatus={0}" -f $ciStatus)
        fncAddEvidenceLine ("UMCIStatus={0}" -f $umciStatus)
    }
    catch {
        fncTestMessage "Unable to query Device Guard / Code Integrity state." "warning"
        fncAddEvidenceLine "DeviceGuardQueryFailed=True"
    }

    Write-Host ""

    # ------------------------------------------------------------
    # AppControl CSP / MDM signals
    # ------------------------------------------------------------
    fncTestMessage "Checking AppControl CSP / MDM policy signals..." "info"

    $cspRegistryCandidates = @(
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AppControl",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\device\ApplicationManagement",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\device\AppControl",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
        "HKLM:\SOFTWARE\Microsoft\Enrollments"
    )

    foreach ($rp in $cspRegistryCandidates) {
        try {
            if (Test-Path -LiteralPath $rp -ErrorAction SilentlyContinue) {
                $cspPresent = $true
                $cspSignals += $rp
                fncTestMessage ("CSP/MDM Signal Present: {0}" -f $rp) "active"
                fncAddEvidenceLine ("CSPSignal={0}" -f $rp)
            }
        }
        catch {}
    }

    if (-not $cspPresent) {
        fncTestMessage "No obvious AppControl CSP / MDM registry signals detected." "info"
        fncAddEvidenceLine "CSPSignal=None"
    }

    Write-Host ""

    # ------------------------------------------------------------
    # WDAC bypass risk signals
    # ------------------------------------------------------------
    fncTestMessage "Assessing WDAC bypass risk signals..." "info"

    # 1. UMCI missing while kernel CI enforced
    if ($kernelEnforced -and -not $umciEnforced) {
        $bypassRisk = $true
        $bypassSignals += "KernelEnforcedWithoutUMCI"
        fncTestMessage "Kernel WDAC enforced but UMCI is not enforced." "warning"
    }

    # 2. Unsigned policy file(s)
    if ($unsignedPolicies.Count -gt 0) {
        $bypassRisk = $true
        $bypassSignals += "UnsignedPolicyFiles"
        fncTestMessage "One or more WDAC policy files are unsigned or failed signature validation." "specpriv"
    }

    # 3. Audit mode only
    if (($kernelAudit -or $umciAudit) -and -not ($kernelEnforced -and $umciEnforced)) {
        $bypassRisk = $true
        $bypassSignals += "AuditOnlyCoverage"
        fncTestMessage "WDAC coverage appears audit-only or partially enforced." "warning"
    }

    # 4. Supplemental policies present
    if ($supplementalCandidates.Count -gt 0) {
        $bypassSignals += "SupplementalPoliciesPresent"
        fncTestMessage ("Supplemental policy candidates detected: {0}" -f $supplementalCandidates.Count) "active"
    }

    # 5. Legacy single policy only
    if ((Test-Path -LiteralPath $legacyPolicy -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath $ciPoliciesDir -ErrorAction SilentlyContinue)) {
        $bypassSignals += "LegacyPolicyLayout"
        fncTestMessage "Legacy WDAC policy layout detected." "info"
    }

    if (-not $bypassSignals -or $bypassSignals.Count -eq 0) {
        fncTestMessage "No obvious WDAC bypass risk signals identified from current checks." "proten"
        fncAddEvidenceLine "BypassSignals=None"
    }
    else {
        foreach ($sig in $bypassSignals) {
            fncAddEvidenceLine ("BypassSignal={0}" -f $sig)
        }
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------

    # No policy at all
    if (-not $policyFiles -or $policyFiles.Count -eq 0) {

        $exploitationText = @"
No WDAC policy files were detected.

Without WDAC, attackers can execute unsigned binaries, custom payloads,
LOLBIN chains, or user-mode tooling without application allowlisting controls.
This materially increases the success rate of initial execution and post-exploitation.
"@

        $remediationText = @"
Deploy a WDAC baseline policy.

Recommended approach:
1) Build a baseline with New-CIPolicy
2) Deploy in audit mode first
3) Validate logs and business application impact
4) Transition to enforced mode
5) Sign policies before production rollout
"@

        fncSubmitFinding `
            -Id ("WDAC-" + (fncShortHashTag "NO_POLICY")) `
            -Title "WDAC Policy Not Present" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Not Detected" `
            -Message "No WDAC policy files were detected on the system." `
            -Recommendation "Deploy and enforce a WDAC policy." `
            -Evidence $policyEvidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Unsigned policy is a priority issue
    if ($unsignedPolicies.Count -gt 0) {

        $exploitationText = @"
One or more WDAC policy files were detected without a valid signature.

Unsigned or unverifiable policies weaken confidence in policy integrity
and may increase the risk of tampering or unauthorised policy replacement
by an attacker with administrative access.
"@

        $remediationText = @"
Use enterprise code-signing for WDAC policies.

Also:
- restrict write access to CodeIntegrity directories
- monitor policy modification attempts
- validate all active and supplemental policies are signed
"@

        fncSubmitFinding `
            -Id ("WDAC-" + (fncShortHashTag "UNSIGNED_POLICY")) `
            -Title "WDAC Policy Signature Validation Failed" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Weak Integrity" `
            -Message "One or more active WDAC policies are unsigned or failed signature validation." `
            -Recommendation "Digitally sign all active WDAC policies and review policy integrity." `
            -Evidence $policyEvidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Audit only
    if (($kernelAudit -or $umciAudit) -and -not ($kernelEnforced -and $umciEnforced)) {

        $exploitationText = @"
WDAC policy coverage appears to be audit-only or only partially enforced.

In this state, blocked execution paths may only generate telemetry rather than prevention.
Attackers can often continue executing payloads while leaving only audit traces.
"@

        $remediationText = @"
Transition WDAC from audit-only to enforced mode once validation is complete.

Ensure both:
- kernel code integrity enforcement
- user mode code integrity enforcement (UMCI)

Review Code Integrity operational logs before moving to full enforcement.
"@

        fncSubmitFinding `
            -Id ("WDAC-" + (fncShortHashTag "AUDIT_OR_PARTIAL")) `
            -Title "WDAC Audit-Only or Partial Enforcement" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Audit Only" `
            -Message "WDAC is present but appears audit-only or only partially enforced." `
            -Recommendation "Move WDAC to fully enforced coverage for both kernel and user mode where feasible." `
            -Evidence $policyEvidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Kernel enforced without UMCI
    if ($kernelEnforced -and -not $umciEnforced) {

        $exploitationText = @"
Kernel-mode code integrity is enforced, but user-mode code integrity is not.

This creates a meaningful gap: attackers may still execute user-mode payloads,
signed-binary proxy execution chains, or other application-layer tooling
despite kernel protections being active.
"@

        $remediationText = @"
Enable UMCI alongside kernel WDAC enforcement where operationally feasible.

This improves coverage against:
- user-mode payload execution
- LOLBIN-assisted execution
- unsigned or unauthorised application launches
"@

        fncSubmitFinding `
            -Id ("WDAC-" + (fncShortHashTag "KERNEL_NO_UMCI")) `
            -Title "WDAC Kernel Enforcement Without UMCI" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Partial Coverage" `
            -Message "Kernel WDAC enforcement is active, but UMCI is not enforced." `
            -Recommendation "Enable UMCI to improve user-mode application control coverage." `
            -Evidence $policyEvidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Strong enforced state
    if ($kernelEnforced -and $umciEnforced) {

        $exploitationText = @"
WDAC appears enforced for both kernel and user mode.

This significantly constrains attacker execution options.
Residual risk typically depends on:
- over-broad allow rules
- risky supplemental policies
- trusted signed binary abuse
- local admin control and policy tampering opportunities
"@

        $remediationText = @"
Maintain WDAC policy hygiene.

Recommended actions:
- periodically review base and supplemental policies
- monitor Code Integrity and AppControl events
- validate signed policy lifecycle
- keep allow rules narrow and controlled
"@

        fncSubmitFinding `
            -Id ("WDAC-" + (fncShortHashTag "FULL_ENFORCEMENT")) `
            -Title "WDAC Enforced for Kernel and User Mode" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Configured" `
            -Message "WDAC policies are present and enforcement appears active for both kernel and user mode." `
            -Recommendation "Maintain WDAC policy integrity and review supplemental policy scope regularly." `
            -Evidence $policyEvidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # Fallback
    $exploitationText = @"
WDAC-related signals were detected, but the effective coverage state could not be clearly classified.

This can happen when policy files exist but enforcement state, UMCI coverage,
supplemental scope, or MDM/CSP deployment posture is inconsistent or unclear.
"@

    $remediationText = @"
Validate WDAC posture manually using:
- Win32_DeviceGuard
- Code Integrity logs
- AppControl policy deployment sources
- active and supplemental policy review

Ensure policy signing and full enforcement are consistently applied.
"@

    fncSubmitFinding `
        -Id ("WDAC-" + (fncShortHashTag "UNKNOWN_STATE")) `
        -Title "WDAC Policy State Unclear" `
        -Category "Application Control" `
        -Severity "Low" `
        -Status "Unknown" `
        -Message "WDAC signals detected but effective enforcement coverage could not be clearly determined." `
        -Recommendation "Review WDAC deployment, supplemental policy scope, and Code Integrity logs." `
        -Evidence $policyEvidence `
        -SourceTests @($testId) `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

Export-ModuleMember -Function @("fncCheckWDACPolicy", "fncGetMappings_WDAC_POLICY_SIGNATURE_CHECK")