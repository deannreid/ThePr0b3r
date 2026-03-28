# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0004"; Name = "Privilege Escalation"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0004/" }
        [pscustomobject]@{ Id = "T1574"; Name = "Hijack Execution Flow"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1574/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-427"; Name = "Uncontrolled Search Path Element"; Url = "https://cwe.mitre.org/data/definitions/427.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-3"; Name = "Access Enforcement"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_APPLOCKER_DLL_ENFORCEMENT { return $script:Mappings }

# ================================================================
# Function: fncCheckAppLockerDllEnforcement
# Purpose : Validate AppLocker DLL rule enforcement posture
# ================================================================
function fncCheckAppLockerDllEnforcement {

    fncSafeSectionHeader "AppLocker DLL Enforcement Validation"
    $Risk = "Safe"
    $RiskReason = "Reads local AppLocker DLL enforcement policy via registry or policy queries only"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Evaluating AppLocker DLL collection posture..." "info"
    Write-Host ""

    $testId = "APPLOCKER-DLL-ENFORCEMENT"

    $baseExploitation = @"
Without DLL enforcement, AppLocker does NOT prevent:
- DLL search-order hijacking
- Service DLL replacement attacks
- Proxy execution via trusted binaries loading attacker-controlled DLLs
- Persistence via writable high-privilege DLL directories
Attackers can drop malicious DLLs into writable locations that precede legitimate paths.
This enables privilege escalation and stealthy execution.
"@

    $baseRemediation = @"
Enable DLL rule collection carefully:
1) Start in Audit Only mode
2) Review Microsoft-Windows-AppLocker/DLL log channel
3) Create allow rules for:
   - Windows directory
   - Program Files
   - Signed vendor applications
4) Transition to Enforced mode once validated
Monitor for operational impact.
"@

    # ------------------------------------------------------------
    # Check AppIDSvc
    # ------------------------------------------------------------
    $svcState = "Unknown"

    try {

        $svc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
        $svcState = [string]$svc.Status

        if ($svcState -eq "Running") {
            fncTestMessage ("AppIDSvc Status: {0}" -f $svcState) "proten"
        }
        else {
            fncTestMessage ("AppIDSvc Status: {0}" -f $svcState) "specpriv"
        }

    }
    catch {
        fncTestMessage "Unable to query AppIDSvc." "warning"
    }

    Write-Host ""

    if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {

        fncTestMessage "Get-AppLockerPolicy cmdlet unavailable." "warning"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_CMDLET_UNAVAILABLE" `
            -Title "Cannot Validate AppLocker DLL Enforcement" `
            -Category "Application Control" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Get-AppLockerPolicy not available; DLL enforcement cannot be validated." `
            -Recommendation "Install RSAT / AppLocker management tooling." `
            -Evidence @("Get-AppLockerPolicy cmdlet missing") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    # ------------------------------------------------------------
    # Retrieve Effective Policy
    # ------------------------------------------------------------
    try {

        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        fncTestMessage "Retrieved effective AppLocker policy." "active"

    }
    catch {

        fncTestMessage "Failed to retrieve effective policy." "warning"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_POLICY_UNREADABLE" `
            -Title "AppLocker DLL Policy Unreadable" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Unknown" `
            -Message "Unable to retrieve effective AppLocker policy." `
            -Recommendation "Validate policy via GPO and event logs." `
            -Evidence @("Get-AppLockerPolicy -Effective failed") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    Write-Host ""

    $dllCollection = $policy.RuleCollections | Where-Object { $_.CollectionType -eq "Dll" }

    if (-not $dllCollection) {

        fncTestMessage "DLL rule collection NOT configured." "specpriv"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_NOT_CONFIGURED" `
            -Title "AppLocker DLL Collection Not Configured" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Not Configured" `
            -Message "No DLL rule collection present in effective policy." `
            -Recommendation "Implement DLL rule collection starting in audit mode." `
            -Evidence @("DLL RuleCollection missing from effective policy") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    $mode = $dllCollection.EnforcementMode
    $ruleCount = @($dllCollection.Rules).Count

    if ($mode -eq "Enforced") {
        fncTestMessage ("DLL Enforcement Mode: {0}" -f $mode) "proten"
    }
    elseif ($mode -match "Audit") {
        fncTestMessage ("DLL Enforcement Mode: {0}" -f $mode) "warning"
    }
    else {
        fncTestMessage ("DLL Enforcement Mode: {0}" -f $mode) "warning"
    }

    fncTestMessage ("DLL Rule Count: {0}" -f $ruleCount) "info"

    Write-Host ""

    # ------------------------------------------------------------
    # Empty Rules
    # ------------------------------------------------------------
    if ($ruleCount -eq 0) {

        fncTestMessage "DLL rule collection contains zero rules." "specpriv"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_EMPTY" `
            -Title "AppLocker DLL Collection Contains No Rules" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Misconfigured" `
            -Message "DLL rule collection present but empty." `
            -Recommendation "Create allow rules before enforcing DLL control." `
            -Evidence @("DLL collection exists but contains zero rules") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    # ------------------------------------------------------------
    # Audit Mode
    # ------------------------------------------------------------
    if ($mode -match "Audit") {

        fncTestMessage "DLL rules operating in Audit Mode." "warning"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_AUDIT" `
            -Title "AppLocker DLL Collection in Audit Mode" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Audit Only" `
            -Message ("DLL collection auditing with {0} rules. AppIDSvc Status='{1}'." -f $ruleCount, $svcState) `
            -Recommendation "Transition DLL collection to Enforced after audit validation." `
            -Evidence @("EnforcementMode=$mode", "Rules=$ruleCount") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    # ------------------------------------------------------------
    # Enforced
    # ------------------------------------------------------------
    if ($mode -eq "Enforced" -and $svcState -eq "Running") {

        fncTestMessage "DLL enforcement active and service running." "proten"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_ENFORCED" `
            -Title "AppLocker DLL Enforcement Active" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Enforced" `
            -Message ("DLL collection enforced with {0} rules." -f $ruleCount) `
            -Recommendation "Maintain DLL enforcement and monitor logs." `
            -Evidence @("Rules=$ruleCount", "AppIDSvc=Running") `
            -SourceTests @($testId)

        return
    }

    # ------------------------------------------------------------
    # Service stopped
    # ------------------------------------------------------------
    if ($mode -eq "Enforced" -and $svcState -ne "Running") {

        fncTestMessage "DLL enforcement configured but AppIDSvc not running." "specpriv"

        fncSubmitFinding `
            -Id "APPLOCKER_DLL_SERVICE_STOPPED" `
            -Title "DLL Enforcement Declared but Service Not Running" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Not Enforced" `
            -Message ("DLL collection shows Enforced but AppIDSvc Status='{0}'." -f $svcState) `
            -Recommendation "Start AppIDSvc and validate DLL enforcement." `
            -Evidence @("EnforcementMode=Enforced", "AppIDSvc=$svcState") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    # ------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------
    fncTestMessage "DLL rule collection present but state unclear." "warning"

    fncSubmitFinding `
        -Id "APPLOCKER_DLL_UNKNOWN" `
        -Title "AppLocker DLL State Unclear" `
        -Category "Application Control" `
        -Severity "Low" `
        -Status "Unknown" `
        -Message ("DLL collection present but state unclear. Mode='{0}'." -f $mode) `
        -Recommendation "Validate DLL enforcement using test DLL load attempts." `
        -Evidence @("EnforcementMode=$mode") `
        -SourceTests @($testId) `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation
}

Export-ModuleMember -Function @("fncCheckAppLockerDllEnforcement", "fncGetMappings_APPLOCKER_DLL_ENFORCEMENT")