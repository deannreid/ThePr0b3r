# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-3"; Name = "Malicious Code Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_DEFENDER_EXCLUSION_PATH_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckDefenderExclusions
# Purpose : Enumerate Microsoft Defender exclusion configuration
# Notes   : Requires Administrator privileges. Detects writable
#           exclusions and creatable excluded directories.
# ================================================================
function fncCheckDefenderExclusions {

    fncPrintSectionHeader "Microsoft Defender Exclusion Validation"

    $Risk = "Low"
    $RiskReason = "Queries Microsoft Defender configuration and filesystem ACLs to identify exclusion abuse risks"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking Microsoft Defender exclusion configuration..." "info"

# ------------------------------------------------------------
# Admin Check
# ------------------------------------------------------------

    $isAdmin = $false

    try {

        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)

        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    } catch {}

    if (-not $isAdmin) {

        fncTestMessage "Administrator privileges required to query Defender exclusions." "disabled"

$exploitationText = @"
This check requires administrative privileges to query Defender configuration.

If an attacker gains administrative access to a system, they may add
Microsoft Defender exclusions to hide malware, persistence mechanisms,
or attacker tooling from security scanning.
"@

$remediationText = @"
Run this validation with administrative privileges.

Ensure only trusted administrators can modify Microsoft Defender settings
and monitor Defender configuration changes via:

- Group Policy auditing
- Endpoint Detection and Response
- Defender security event logs
"@

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "ADMIN_REQUIRED")) `
            -Category "Defense Evasion" `
            -Title "Defender Exclusion Check Requires Administrative Privileges" `
            -Severity "Low" `
            -Status "Mixed / Unclear" `
            -Message "Administrator privileges required to enumerate Defender exclusions." `
            -Recommendation "Run the check with administrative privileges." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Query Defender Preferences
# ------------------------------------------------------------

    fncTestMessage "Querying Microsoft Defender configuration..." "info"

    $exclusionPaths      = @()
    $exclusionProcesses  = @()
    $exclusionExtensions = @()

    try {

        $prefs = Get-MpPreference

        if ($prefs.ExclusionPath)      { $exclusionPaths      = $prefs.ExclusionPath }
        if ($prefs.ExclusionProcess)  { $exclusionProcesses  = $prefs.ExclusionProcess }
        if ($prefs.ExclusionExtension){ $exclusionExtensions = $prefs.ExclusionExtension }

    } catch {

        fncTestMessage "Unable to query Defender preferences." "warning"
        return
    }

# ------------------------------------------------------------
# Aggregate results
# ------------------------------------------------------------

    $total = $exclusionPaths.Count + $exclusionProcesses.Count + $exclusionExtensions.Count

    fncTestMessage ("Total exclusions detected: {0}" -f $total) "active"

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/001/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus" "link"

# ------------------------------------------------------------
# No exclusions detected
# ------------------------------------------------------------

    if ($total -eq 0) {

        fncTestMessage "No Microsoft Defender exclusions detected." "proten"

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "NO_EXCLUSIONS")) `
            -Category "Defense Evasion" `
            -Title "No Microsoft Defender Exclusions Detected" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "No Defender exclusions detected." `
            -Recommendation "Maintain minimal exclusion configuration." `
            -Exploitation "No Defender exclusion bypass paths detected." `
            -Remediation "No remediation required."

        return
    }

# ------------------------------------------------------------
# Print exclusions
# ------------------------------------------------------------

    fncTestMessage ("Defender exclusions detected: {0}" -f $total) "specpriv"

    foreach ($p in $exclusionPaths | Select-Object -First 10) {
        fncTestMessage ("Path exclusion detected: {0}" -f $p) "active"
    }

    foreach ($p in $exclusionProcesses | Select-Object -First 10) {
        fncTestMessage ("Process exclusion detected: {0}" -f $p) "active"
    }

    foreach ($p in $exclusionExtensions | Select-Object -First 10) {
        fncTestMessage ("Extension exclusion detected: {0}" -f $p) "active"
    }

# ------------------------------------------------------------
# Write permission mask
# ------------------------------------------------------------

$writeRights = `
    [System.Security.AccessControl.FileSystemRights]::Write `
    -bor [System.Security.AccessControl.FileSystemRights]::Modify `
    -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
    -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles `
    -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
    -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
    -bor [System.Security.AccessControl.FileSystemRights]::FullControl

# ------------------------------------------------------------
# Detect writable exclusion paths
# ------------------------------------------------------------

    $dangerousPaths = @()

    foreach ($path in $exclusionPaths) {

        try {

            if (-not (Test-Path $path)) { continue }

            $acl = Get-Acl $path

            foreach ($ace in $acl.Access) {

                $identity = $ace.IdentityReference.ToString()

                if (
                    ($ace.FileSystemRights -band $writeRights) -and
                    (
                        $identity -match "Authenticated Users" -or
                        $identity -match "Users" -or
                        $identity -match "Everyone"
                    )
                ) {

                    fncTestMessage ("Writable Defender exclusion path detected: {0}" -f $path) "specpriv"

                    $dangerousPaths += [PSCustomObject]@{
                        Path = $path
                        Principal = $identity
                    }
                }
            }

        } catch {

            fncTestMessage ("Failed evaluating ACLs for {0}" -f $path) "warning"
        }
    }

# ------------------------------------------------------------
# Detect creatable excluded directories
# ------------------------------------------------------------

    $creatablePaths = @()

    foreach ($path in $exclusionPaths) {

        if (Test-Path $path) { continue }

        try {

            fncTestMessage ("Excluded directory missing: {0}" -f $path) "warning"

            $parent = Split-Path $path -Parent

            if (-not (Test-Path $parent)) { continue }

            $acl = Get-Acl $parent

            foreach ($ace in $acl.Access) {

                $identity = $ace.IdentityReference.ToString()

                if (
                    ($ace.FileSystemRights -band $writeRights) -and
                    (
                        $identity -match "Authenticated Users" -or
                        $identity -match "Users" -or
                        $identity -match "Everyone"
                    )
                ) {

                    fncTestMessage ("Parent directory writable: {0}" -f $parent) "specpriv"

                    $creatablePaths += [PSCustomObject]@{
                        MissingPath = $path
                        Parent = $parent
                        Principal = $identity
                    }
                }
            }

        } catch {

            fncTestMessage ("Failed evaluating missing exclusion path {0}" -f $path) "warning"
        }
    }

# ------------------------------------------------------------
# Critical: Writable exclusions
# ------------------------------------------------------------

    if ($dangerousPaths.Count -gt 0) {

        $pathList = ($dangerousPaths | ForEach-Object { "$($_.Path) [$($_.Principal)]" }) -join ", "

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "WRITABLE_EXCLUSION_PATH")) `
            -Category "Defense Evasion" `
            -Title "User Writable Defender Exclusion Path Detected" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("Writable Defender exclusion paths detected: {0}" -f $pathList) `
            -Recommendation "Remove exclusions from user-writable directories."

        return
    }

# ------------------------------------------------------------
# Critical: Creatable exclusions
# ------------------------------------------------------------

    if ($creatablePaths.Count -gt 0) {

        $pathList = ($creatablePaths | ForEach-Object {
            "$($_.MissingPath) (Parent writable by $($_.Principal))"
        }) -join ", "

        fncSubmitFinding `
            -Id ("DEFENDER-" + (fncShortHashTag "CREATABLE_EXCLUSION_PATH")) `
            -Category "Defense Evasion" `
            -Title "Creatable Defender Exclusion Directory Detected" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("Excluded directories attackers could create: {0}" -f $pathList) `
            -Recommendation "Remove exclusions or restrict parent directory permissions."

        return
    }

# ------------------------------------------------------------
# Standard Exclusion Finding
# ------------------------------------------------------------

    $all = @()
    $all += $exclusionPaths
    $all += $exclusionProcesses
    $all += $exclusionExtensions

    $list = ($all | Select-Object -Unique) -join ", "

    fncSubmitFinding `
        -Id ("DEFENDER-" + (fncShortHashTag "EXCLUSIONS_PRESENT")) `
        -Category "Defense Evasion" `
        -Title "Microsoft Defender Exclusions Detected" `
        -Severity "Medium" `
        -Status "Detected" `
        -Message ("Defender exclusions detected: {0}" -f $list) `
        -Recommendation "Review and remove unnecessary Defender exclusions."

}

Export-ModuleMember -Function @("fncCheckDefenderExclusions", "fncGetMappings_DEFENDER_EXCLUSION_PATH_CHECK")