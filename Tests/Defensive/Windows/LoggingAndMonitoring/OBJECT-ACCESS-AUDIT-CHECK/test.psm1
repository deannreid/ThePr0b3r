# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1003"; Name = "OS Credential Dumping"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1003/" }
        [pscustomobject]@{ Id = "T1070"; Name = "Indicator Removal on Host"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1070/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-778"; Name = "Insufficient Logging"; Url = "https://cwe.mitre.org/data/definitions/778.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AU-2"; Name = "Audit Events"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Auditable Events"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_OBJECT_ACCESS_AUDIT_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckObjectAccessAudit
# Purpose : Identify gaps in object access auditing attackers abuse
# Notes   : Focuses on whether file system and registry object access
#           auditing is configured well enough to catch credential
#           store access, tampering, and sensitive file interaction.
# ================================================================
function fncCheckObjectAccessAudit {

    fncPrintSectionHeader "Object Access Audit Exposure"

    $Risk = "Low"
    $RiskReason = "Performs read-only inspection of audit policy configuration and SACL coverage on sensitive files and registry keys"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Assessing object access audit visibility..." "info"

# ------------------------------------------------------------
# Base Text
# ------------------------------------------------------------

$baseExploitation = @"
Object access auditing determines whether Windows records access to
sensitive files, folders, and registry locations.

From a red team perspective, weak object access auditing creates blind
spots during operations involving:

- Registry hive access
- SAM and SECURITY hive extraction
- Access to credential material
- File collection from sensitive directories
- Tampering with security tooling or log locations

If object access auditing is disabled, attackers can interact with
high-value targets without generating usable telemetry.

This reduces blue team visibility into credential access, staging,
tampering, and follow-on data collection.
"@

$baseRemediation = @"
Enable object access auditing for relevant categories and apply SACLs
to high-value files, folders, and registry paths.

Recommended actions:

1) Enable File System auditing.
2) Enable Registry auditing.
3) Apply SACLs to sensitive locations such as:
   - SAM / SECURITY / SYSTEM hives
   - LSASS-related dump paths
   - Credential material stores
   - Security tool directories
   - Log storage locations
4) Forward relevant events to centralized monitoring.
5) Regularly review high-value audit coverage.
"@

# ------------------------------------------------------------
# Administrator Check
# ------------------------------------------------------------

$isAdmin = $false

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

if (-not $isAdmin) {

    fncTestMessage "Administrator privileges required to validate object access auditing." "specpriv"

    $exploitationText = @"
Without administrative privileges the audit configuration cannot be fully inspected. 
This prevents validation of file and registry auditing coverage.
"@

    $remediationText = "Run the validation with administrative privileges."

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "ADMIN_REQUIRED")) `
        -Category "Defense Evasion" `
        -Title "Object Access Audit Validation Requires Administrative Privileges" `
        -Severity "Low" `
        -Status "Mixed / Unclear" `
        -Message "Administrator privileges required to enumerate object access audit configuration." `
        -Recommendation "Run the check with administrative privileges." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    return
}

# ------------------------------------------------------------
# Query Audit Policy
# ------------------------------------------------------------

$fileSystemAudit = $false
$registryAudit   = $false
$auditRaw        = @()

try {

    $auditRaw = auditpol /get /subcategory:* 2>$null

    foreach ($line in $auditRaw) {

        if ($line -match "File System" -and $line -match "Success|Failure") {
            $fileSystemAudit = $true
        }

        if ($line -match "Registry" -and $line -match "Success|Failure") {
            $registryAudit = $true
        }
    }

    fncTestMessage "Object access audit policy queried successfully." "active"

} catch {

    fncTestMessage "Unable to query object access audit policy." "warning"

    $exploitationText = "Attackers benefit when defenders cannot verify telemetry coverage."

    $remediationText = "Ensure audit policy can be queried and reviewed centrally."

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "QUERY_FAILED")) `
        -Category "Defense Evasion" `
        -Title "Object Access Audit Policy Could Not Be Queried" `
        -Severity "Medium" `
        -Status "Mixed / Unclear" `
        -Message "The host did not return object access audit policy information." `
        -Recommendation "Validate audit policy configuration manually." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    return
}

# ------------------------------------------------------------
# Audit Subcategory Visibility
# ------------------------------------------------------------

if ($fileSystemAudit) {

    fncTestMessage "File System object access auditing enabled." "proten"

} else {

    fncTestMessage "File System object access auditing not enabled." "specpriv"

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "FILESYSTEM_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "File System Object Access Auditing Disabled" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "File System object access auditing is not enabled." `
        -Recommendation "Enable File System auditing for sensitive locations." `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation
}

if ($registryAudit) {

    fncTestMessage "Registry object access auditing enabled." "proten"

} else {

    fncTestMessage "Registry object access auditing not enabled." "specpriv"

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "REGISTRY_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "Registry Object Access Auditing Disabled" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "Registry object access auditing is not enabled." `
        -Recommendation "Enable Registry auditing for sensitive keys and hives." `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation
}

# ------------------------------------------------------------
# Check High-Value File SACL Coverage
# ------------------------------------------------------------

$saclWeakTargets = @()

$fileTargets = @(
"$env:windir\System32\config\SAM",
"$env:windir\System32\config\SECURITY",
"$env:windir\System32\config\SYSTEM"
)

foreach ($target in $fileTargets) {

    try {

        if (-not (Test-Path $target)) {
            fncTestMessage ("Sensitive file not present: {0}" -f $target) "warning"
            continue
        }

        $acl = Get-Acl -Path $target -Audit -ErrorAction SilentlyContinue

        if (-not $acl.Audit -or $acl.Audit.Count -eq 0) {

            $saclWeakTargets += $target
            fncTestMessage ("No SACL present on sensitive file: {0}" -f $target) "specpriv"

        } else {

            fncTestMessage ("SACL present on sensitive file: {0}" -f $target) "active"
        }

    } catch {

        fncTestMessage ("Unable to inspect SACL for {0}" -f $target) "warning"
    }
}

# ------------------------------------------------------------
# Registry SACL Visibility Hint
# ------------------------------------------------------------

$registryTargets = @(
"HKLM:\SAM",
"HKLM:\SECURITY",
"HKLM:\SYSTEM"
)

foreach ($regTarget in $registryTargets) {

    try {

        $acl = Get-Acl -Path $regTarget -Audit -ErrorAction SilentlyContinue

        if ($acl -and $acl.Audit -and $acl.Audit.Count -gt 0) {

            fncTestMessage ("SACL present on sensitive registry target: {0}" -f $regTarget) "active"

        } else {

            fncTestMessage ("No SACL present on sensitive registry target: {0}" -f $regTarget) "warning"
        }

    } catch {

        fncTestMessage ("Unable to inspect registry SACL for {0}" -f $regTarget) "warning"
    }
}

# ------------------------------------------------------------
# Summarise Weak Coverage
# ------------------------------------------------------------

if ($saclWeakTargets.Count -gt 0) {

    $weakList = ($saclWeakTargets | Select-Object -Unique) -join ", "

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "SACL_GAPS")) `
        -Category "Defense Evasion" `
        -Title "Sensitive Object Audit Coverage Weak" `
        -Severity "Medium" `
        -Status "Likely Exposed" `
        -Message ("Sensitive files missing SACL coverage: {0}" -f $weakList) `
        -Recommendation "Apply SACLs to sensitive credential and security files." `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation

} elseif ($fileSystemAudit -and $registryAudit) {

    fncTestMessage "Object access audit coverage appears present for key categories." "proten"

    fncSubmitFinding `
        -Id ("OBJAUDIT-" + (fncShortHashTag "COVERAGE_PRESENT")) `
        -Category "Defense Evasion" `
        -Title "Object Access Audit Coverage Present" `
        -Severity "Info" `
        -Status "Protected" `
        -Message "Object access audit categories are enabled and key sensitive files show audit coverage." `
        -Recommendation "Maintain current audit posture and review high-value SACLs regularly." `
        -Exploitation $baseExploitation `
        -Remediation "No remediation required."
}

fncTestMessage "https://attack.mitre.org/techniques/T1003/" "link"
fncTestMessage "https://attack.mitre.org/techniques/T1112/" "link"

}

Export-ModuleMember -Function @("fncCheckObjectAccessAudit", "fncGetMappings_OBJECT_ACCESS_AUDIT_CHECK")