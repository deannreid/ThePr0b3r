# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1059.001"; Name = "Command and Scripting Interpreter"; Tactic = "Execution"; Url = "https://attack.mitre.org/techniques/T1059/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-7"; Name = "Least Functionality"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_EXECUTION_POLICY_GLOBAL_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckExecutionPolicyGlobal
# Purpose : Evaluate PowerShell execution policy posture
# ================================================================
function fncCheckExecutionPolicyGlobal {

    fncSafeSectionHeader "PowerShell Execution Policy Assessment"
    $Risk = "Safe"
    $RiskReason = "Queries PowerShell execution policy settings which are common administrative operations"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Enumerating execution policy across all scopes..." "info"
    Write-Host ""

    $testId = "EXECUTION-POLICY-GLOBAL-CHECK"

    # ------------------------------------------------------------
    # Retrieve all scope policies
    # ------------------------------------------------------------
    $policies = @()
    try {
        $policies = Get-ExecutionPolicy -List
    }
    catch {
        fncTestMessage "Unable to query execution policy." "warning"

        fncSubmitFinding `
            -Id "EXEC-POLICY-QUERY_FAILED" `
            -Title "Unable to Query PowerShell Execution Policy" `
            -Category "Application Control" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Get-ExecutionPolicy query failed." `
            -Recommendation "Verify PowerShell configuration and required permissions." `
            -Evidence @("Get-ExecutionPolicy -List failed") `
            -SourceTests @($testId) `
            -Exploitation "Unable to determine execution policy posture." `
            -Remediation "Ensure PowerShell is functioning and accessible."

        return
    }

    foreach ($p in $policies) {

        if ($p.ExecutionPolicy -eq "Bypass" -or $p.ExecutionPolicy -eq "Unrestricted") {
            $lvl = "specpriv"
        }
        else {
            $lvl = "info"
        }

        fncTestMessage ("{0,-15} : {1}" -f $p.Scope, $p.ExecutionPolicy) $lvl
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Determine effective policy
    # ------------------------------------------------------------
    $effective = $null
    try {

        $effective = Get-ExecutionPolicy

        if ($effective -eq "Bypass" -or $effective -eq "Unrestricted") {
            fncTestMessage ("Effective Execution Policy: {0}" -f $effective) "specpriv"
        }
        else {
            fncTestMessage ("Effective Execution Policy: {0}" -f $effective) "proten"
        }

    }
    catch {}

    Write-Host ""

    # ------------------------------------------------------------
    # Language Mode Detection
    # ------------------------------------------------------------
    $languageMode = $ExecutionContext.SessionState.LanguageMode

    if ($languageMode -eq "ConstrainedLanguage") {
        fncTestMessage ("PowerShell Language Mode: {0}" -f $languageMode) "proten"
    }
    else {
        fncTestMessage ("PowerShell Language Mode: {0}" -f $languageMode) "warning"
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Exploitation Narrative Builder
    # ------------------------------------------------------------
    $exploitationText = @"
PowerShell execution policy determines how scripts are treated by the host.

Observed Effective Policy: $effective
Observed Language Mode: $languageMode

Execution policies such as:
- Bypass
- Unrestricted
- Undefined (all scopes)

allow arbitrary script execution without signature enforcement.

Attackers commonly:
- Execute payloads directly from memory
- Use -ExecutionPolicy Bypass at runtime
- Load encoded commands via -EncodedCommand
- Deliver fileless malware

IMPORTANT:
Execution policy is NOT a security boundary.
It can be overridden per-process.
True protection requires:
- WDAC
- AppLocker
- Constrained Language Mode
- ASR rules
"@

    $remediationText = @"
Hardening Recommendations:

1) Set Execution Policy via Group Policy:
   Computer Configuration â†’ Administrative Templates â†’ Windows Components â†’ PowerShell

2) Recommended baseline:
   RemoteSigned (minimum)
   AllSigned (higher assurance)

3) Combine with:
   - WDAC enforcement
   - AppLocker rules for powershell.exe and pwsh.exe
   - Constrained Language Mode via WDAC
   - Script Block Logging enabled
   - AMSI operational and monitored

4) Monitor for:
   - powershell.exe -ExecutionPolicy Bypass
   - -EncodedCommand usage
   - Parent process anomalies (Office, wscript, mshta)

Execution policy alone does NOT prevent attacker execution.
"@

    # ------------------------------------------------------------
    # Risk Evaluation
    # ------------------------------------------------------------
    if ($effective -eq "Bypass" -or $effective -eq "Unrestricted") {

        fncTestMessage "Weak PowerShell execution policy detected." "specpriv"

        fncSubmitFinding `
            -Id ("EXEC-POLICY-" + (fncShortHashTag "WEAK_POLICY")) `
            -Title "Weak PowerShell Execution Policy" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("Effective execution policy is '{0}'." -f $effective) `
            -Recommendation "Set execution policy to RemoteSigned or AllSigned via Group Policy." `
            -Evidence @("ExecutionPolicy=$effective") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    if ($languageMode -ne "ConstrainedLanguage") {

        fncTestMessage "PowerShell running in FullLanguage mode." "warning"

        fncSubmitFinding `
            -Id ("EXEC-POLICY-" + (fncShortHashTag "FULL_LANGUAGE_MODE")) `
            -Title "PowerShell Running in Full Language Mode" `
            -Category "Application Control" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "PowerShell session is running in FullLanguage mode." `
            -Recommendation "Consider WDAC policy to enforce ConstrainedLanguage where appropriate." `
            -Evidence @("LanguageMode=$languageMode") `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Hardened State
    # ------------------------------------------------------------
    fncTestMessage "PowerShell execution policy hardened." "proten"

    fncSubmitFinding `
        -Id ("EXEC-POLICY-" + (fncShortHashTag "HARDENED")) `
        -Title "PowerShell Execution Policy Hardened" `
        -Category "Application Control" `
        -Severity "Info" `
        -Status "Configured" `
        -Message ("Execution Policy: {0}, Language Mode: {1}" -f $effective, $languageMode) `
        -Recommendation "Maintain policy enforcement and monitor PowerShell telemetry." `
        -Evidence @(
        ("ExecutionPolicy=$effective"),
        ("LanguageMode=$languageMode")
    ) `
        -SourceTests @($testId) `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    Write-Host ""
}

Export-ModuleMember -Function @("fncCheckExecutionPolicyGlobal", "fncGetMappings_EXECUTION_POLICY_GLOBAL_CHECK")