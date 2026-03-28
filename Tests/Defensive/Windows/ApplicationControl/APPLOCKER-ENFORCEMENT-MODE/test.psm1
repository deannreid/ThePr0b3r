# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0002"; Name = "Execution"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0002/" }
        [pscustomobject]@{ Id = "T1218"; Name = "Signed Binary Proxy Execution"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1218/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-7"; Name = "Least Functionality"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AC-3"; Name = "Access Enforcement"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_APPLOCKER_ENFORCEMENT_MODE { return $script:Mappings }

# ================================================================
# Function: fncCheckAppLockerEnforcementMode
# Purpose : Validate AppLocker collection enforcement / audit / disabled
# Notes   : Console output aligned to output key legend
# ================================================================
function fncCheckAppLockerEnforcementMode {

    fncSafeSectionHeader "AppLocker Enforcement Mode Validation"
    $Risk = "Safe"
    $RiskReason = "Queries AppLocker enforcement mode through policy inspection without modifying state"

    fncPrintRisk $Risk $RiskReason
    fncTestMessage "Checking Application Identity service (AppIDSvc)..." "info"

    $testId = "APPLOCKER-ENFORCEMENT-MODE"

    # ------------------------------------------------------------
    # Exploitation / Remediation (base)
    # ------------------------------------------------------------
    $baseExploitation = @"
AppLocker governs application allow-listing for executables, scripts, installers and DLLs.
If AppLocker is not configured, not enforced, or only auditing, attackers can execute:
- Unsigned payloads and custom binaries
- Script-based tooling (PowerShell, WSH, mshta)
- MSI-based execution chains
- LOLBIN proxy execution paths
This increases malware execution likelihood and enables post-exploitation tooling to run freely.
"@

    $baseRemediation = @"
Deploy AppLocker using Group Policy (recommended) with a staged rollout:
1) Start in Audit Only to observe what would be blocked.
2) Create explicit allow rules for business apps, admin tools, update mechanisms.
3) Move to Enforced mode once audit logs confirm low false positives.
4) Keep AppIDSvc set to Automatic and Running on all targeted systems.
"@

    # ------------------------------------------------------------
    # Check AppIDSvc
    # ------------------------------------------------------------
    $svc = $null
    $svcState = "Unknown"
    $svcStartType = "Unknown"

    try {

        $svc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
        $svcState = [string]$svc.Status

        if ($svcState -eq "Running") {
            fncTestMessage ("AppIDSvc Status: {0}" -f $svcState) "proten"
        }
        else {
            fncTestMessage ("AppIDSvc Status: {0}" -f $svcState) "specpriv"
        }

        try {
            $svcCim = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction Stop
            $svcStartType = [string]$svcCim.StartMode
            fncTestMessage ("AppIDSvc StartMode: {0}" -f $svcStartType) "info"
        }
        catch {}

    }
    catch {
        fncTestMessage "AppIDSvc service not found or cannot be queried." "warning"
    }

    Write-Host ""
    fncTestMessage "Retrieving effective AppLocker policy (Get-AppLockerPolicy -Effective)..." "info"

    # ------------------------------------------------------------
    # Cmdlet availability
    # ------------------------------------------------------------
    if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {

        fncTestMessage "Get-AppLockerPolicy cmdlet not available on this host." "warning"
        fncTestMessage "Falling back to registry presence check (SrpV2)..." "info"

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

        if (Test-Path $regPath) {

            fncTestMessage "SrpV2 registry policy path present." "active"

            fncSubmitFinding `
                -Id ("APPLOCKER-" + (fncShortHashTag "REGISTRY_PRESENT_CMDLET_MISSING")) `
                -Title "AppLocker Registry Policy Present (Cmdlet Unavailable)" `
                -Category "Application Control" `
                -Severity "Info" `
                -Status "Detected" `
                -Message ("SrpV2 keys present but Get-AppLockerPolicy unavailable. AppIDSvc Status='{0}', StartMode='{1}'." -f $svcState, $svcStartType) `
                -Recommendation "Validate AppLocker enforcement mode via GPO/Local Policy tooling." `
                -Evidence @("Registry: HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2 present") `
                -SourceTests @($testId) `
                -Exploitation $baseExploitation `
                -Remediation $baseRemediation

        }
        else {

            fncTestMessage "No AppLocker (SrpV2) policy detected in registry." "specpriv"

            fncSubmitFinding `
                -Id ("APPLOCKER-" + (fncShortHashTag "NOT_CONFIGURED")) `
                -Title "AppLocker Not Configured" `
                -Category "Application Control" `
                -Severity "Medium" `
                -Status "Not Detected" `
                -Message ("No SrpV2 policy keys found. AppIDSvc Status='{0}', StartMode='{1}'." -f $svcState, $svcStartType) `
                -Recommendation "Implement AppLocker allow-listing policy." `
                -Evidence @("Registry key missing: HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2") `
                -SourceTests @($testId) `
                -Exploitation $baseExploitation `
                -Remediation $baseRemediation

        }

        Write-Host ""
        return
    }

    # ------------------------------------------------------------
    # Retrieve Effective Policy
    # ------------------------------------------------------------
    $policy = $null
    try {

        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        fncTestMessage "Successfully retrieved effective AppLocker policy." "active"

    }
    catch {

        fncTestMessage "Failed to retrieve effective AppLocker policy." "warning"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "POLICY_UNREADABLE")) `
            -Title "AppLocker Policy Could Not Be Retrieved" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Unknown" `
            -Message ("Get-AppLockerPolicy failed. AppIDSvc Status='{0}', StartMode='{1}'." -f $svcState, $svcStartType) `
            -Recommendation "Validate AppLocker via GPO tooling and event logs." `
            -Evidence @("Get-AppLockerPolicy -Effective failed") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        Write-Host ""
        return
    }

    Write-Host ""

    # ------------------------------------------------------------
    # Determine enforcement mode per collection
    # ------------------------------------------------------------
    $collections = @()
    try { $collections = @($policy.RuleCollections) } catch { $collections = @() }

    if (-not $collections -or $collections.Count -eq 0) {

        fncTestMessage "No AppLocker rule collections found in effective policy." "specpriv"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "NO_COLLECTIONS")) `
            -Title "AppLocker Policy Contains No Rule Collections" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Misconfigured" `
            -Message ("No RuleCollections returned. AppIDSvc Status='{0}'." -f $svcState) `
            -Recommendation "Create rule collections and validate in audit mode before enforcing." `
            -Evidence @("RuleCollections=0") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        Write-Host ""
        return
    }

    $results = @()
    foreach ($rc in $collections) {

        $rcType = ""
        try { $rcType = [string]$rc.CollectionType } catch { $rcType = "" }
        if (-not $rcType) { continue }

        $mode = "Unknown"
        try { $mode = [string]$rc.EnforcementMode } catch { $mode = "Unknown" }

        $ruleCount = 0
        try { $ruleCount = @($rc.Rules).Count } catch { $ruleCount = 0 }

        $results += [PSCustomObject]@{
            Collection = $rcType
            Mode       = $mode
            Rules      = $ruleCount
        }
    }

    fncTestMessage "AppLocker Rule Collection Posture:"

    foreach ($r in $results) {

        if ($r.Mode -match "Enforced") {
            $lvl = "proten"
        }
        elseif ($r.Mode -match "Audit") {
            $lvl = "warning"
        }
        elseif ($r.Mode -match "NotConfigured") {
            $lvl = "specpriv"
        }
        else {
            $lvl = "info"
        }

        fncTestMessage ("{0}: {1} (Rules: {2})" -f $r.Collection, $r.Mode, $r.Rules) $lvl
    }

    Write-Host ""
    fncTestMessage ("AppIDSvc required for enforcement. Current: Status='{0}', StartMode='{1}'" -f $svcState, $svcStartType) "info"
    Write-Host ""

    # ------------------------------------------------------------
    # Findings by condition
    # ------------------------------------------------------------
    $hasAnyRules = (($results | Measure-Object -Property Rules -Sum).Sum -gt 0)
    $anyEnforced = ($results | Where-Object { $_.Mode -match "Enforced" }).Count -gt 0
    $anyAudit = ($results | Where-Object { $_.Mode -match "AuditOnly|Audit" }).Count -gt 0
    $anyNotCfg = ($results | Where-Object { $_.Mode -match "NotConfigured|Not Configured" }).Count -gt 0

    $serviceBlocking = ($svcState -ne "Running")

    if (-not $hasAnyRules) {

        fncTestMessage "AppLocker policy present but contains zero rules." "specpriv"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "EMPTY_POLICY")) `
            -Title "AppLocker Policy Present but Contains No Rules" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Misconfigured" `
            -Message ("Effective policy contains 0 rules. Collections: {0}" -f (($results | ForEach-Object { "$($_.Collection)=$($_.Mode)" }) -join ", ")) `
            -Recommendation "Implement allow-list rules and validate in audit mode first." `
            -Evidence @("TotalRules=0") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    if ($anyEnforced -and $serviceBlocking) {

        fncTestMessage "AppLocker enforcement declared but AppIDSvc not running." "specpriv"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "ENFORCED_BUT_SERVICE_STOPPED")) `
            -Title "AppLocker Enforcement Declared but Service Not Running" `
            -Category "Application Control" `
            -Severity "High" `
            -Status "Not Enforced" `
            -Message ("Collections show Enforced, but AppIDSvc Status='{0}', StartMode='{1}'." -f $svcState, $svcStartType) `
            -Recommendation "Start AppIDSvc and validate AppLocker enforcement end-to-end." `
            -Evidence @("AppIDSvc=$svcState", "StartMode=$svcStartType") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    if ($anyAudit -and -not $anyEnforced) {

        fncTestMessage "AppLocker deployed but only auditing." "warning"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "AUDIT_ONLY")) `
            -Title "AppLocker Deployed but Only Auditing" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Audit Only" `
            -Message ("Collections in Audit Only with no enforced collections. AppIDSvc Status='{0}'." -f $svcState) `
            -Recommendation "Transition to Enforced mode once audit logs confirm low false positives." `
            -Evidence @("CollectionsAuditOnly") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    if ($anyNotCfg) {

        fncTestMessage "Mixed or partially configured AppLocker collections detected." "warning"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "MIXED_OR_PARTIAL")) `
            -Title "AppLocker Partially Configured (Mixed Collection Posture)" `
            -Category "Application Control" `
            -Severity "Medium" `
            -Status "Partial Coverage" `
            -Message ("Mixed enforcement posture detected. AppIDSvc Status='{0}'." -f $svcState) `
            -Recommendation "Ensure consistent enforcement across high-risk collections (EXE/Script/MSI)." `
            -Evidence @("MixedCollections") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

    }

    if ($anyEnforced -and -not $serviceBlocking) {

        fncTestMessage "AppLocker enforcement active." "proten"

        fncSubmitFinding `
            -Id ("APPLOCKER-" + (fncShortHashTag "ENFORCED_OK")) `
            -Title "AppLocker Enforcement Active" `
            -Category "Application Control" `
            -Severity "Info" `
            -Status "Enforced" `
            -Message ("Enforced collections detected and AppIDSvc is running.") `
            -Recommendation "Maintain enforcement and close gaps in any non-enforced high-risk collections." `
            -Evidence @("AppIDSvc=Running") `
            -SourceTests @($testId) `
            -Exploitation $baseExploitation `
            -Remediation $baseRemediation

        return
    }

    fncTestMessage "AppLocker configuration detected but state classification unclear." "warning"

    fncSubmitFinding `
        -Id ("APPLOCKER-" + (fncShortHashTag "UNKNOWN_STATE")) `
        -Title "AppLocker Configuration Detected (Unclear Effective State)" `
        -Category "Application Control" `
        -Severity "Low" `
        -Status "Unknown" `
        -Message ("AppLocker policy retrieved but enforcement posture unclear. AppIDSvc Status='{0}'." -f $svcState) `
        -Recommendation "Validate AppLocker behaviour using controlled test binaries/scripts and inspect event logs." `
        -Evidence @("StateClassificationFailed") `
        -SourceTests @($testId) `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation
}

Export-ModuleMember -Function @("fncCheckAppLockerEnforcementMode", "fncGetMappings_APPLOCKER_ENFORCEMENT_MODE")