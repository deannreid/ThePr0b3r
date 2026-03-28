# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1548.003"; Name = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"; Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1548/003/" }
        [pscustomobject]@{ Id = "T1078";     Name = "Valid Accounts";                                           Tactic = "Defense Evasion";     Url = "https://attack.mitre.org/techniques/T1078/" }
        [pscustomobject]@{ Id = "T1068";     Name = "Exploitation for Privilege Escalation";                    Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1068/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-269"; Name = "Improper Privilege Management";                             Url = "https://cwe.mitre.org/data/definitions/269.html" }
        [pscustomobject]@{ Id = "CWE-732"; Name = "Incorrect Permission Assignment for Critical Resource";      Url = "https://cwe.mitre.org/data/definitions/732.html" }
        [pscustomobject]@{ Id = "CWE-272"; Name = "Least Privilege Violation";                                 Url = "https://cwe.mitre.org/data/definitions/272.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6";  Name = "Least Privilege";         Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings";  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SI-2";  Name = "Flaw Remediation";        Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "5.3.1"; Name = "Ensure sudo is installed";                                    Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "sudo is required to provide controlled privilege escalation with full audit trail." }
        [pscustomobject]@{ Id = "5.3.2"; Name = "Ensure sudo commands use pty";                               Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Require a TTY for sudo to prevent non-interactive privilege escalation." }
        [pscustomobject]@{ Id = "5.3.3"; Name = "Ensure sudo log file exists";                                Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "A dedicated sudo log file provides an independent audit trail of privilege use." }
        [pscustomobject]@{ Id = "5.3.6"; Name = "Ensure sudo authentication timeout is configured correctly"; Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Limit the duration of cached sudo credentials to reduce the window for session hijacking." }
        [pscustomobject]@{ Id = "5.3.7"; Name = "Ensure access to the su command is restricted";             Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Restrict su to members of an authorised group to limit lateral privilege movement." }
    )
}

function fncGetMappings_LINUX_SUDO_CONFIG { return $script:Mappings }

# ================================================================
# Function: fncCheckLinuxSudoConfig
# Purpose : Evaluate sudo configuration and privilege escalation
#           surface on Linux hosts
# ================================================================
function fncCheckLinuxSudoConfig {

    fncSafeSectionHeader "Sudo Configuration Security Assessment"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Reads /etc/sudoers, /etc/sudoers.d and sudo version output only - no privilege operations performed"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating sudo configuration security posture..." "info"
    Write-Host ""

    $testId       = "LINUX-SUDO-CONFIG"
    $sudoersPath  = "/etc/sudoers"
    $sudoersDDir  = "/etc/sudoers.d"

    # ----------------------------------------------------------------
    # sudoers file present
    # ----------------------------------------------------------------
    if (-not (Test-Path $sudoersPath)) {
        fncTestMessage "sudoers file not found at $sudoersPath - sudo may not be installed." "warning"
        return
    }

    # ----------------------------------------------------------------
    # /etc/sudoers permissions
    # ----------------------------------------------------------------
    fncTestMessage "Checking /etc/sudoers file permissions..." "info"

    try {

        $perms = (& bash -c "stat -c '%a' /etc/sudoers 2>/dev/null").Trim()

        if ($perms -and $perms -notin @("440", "0440")) {

            $exploitation = @"
A world-readable sudoers file leaks the full privilege escalation map to any local user.
A writable sudoers file allows direct injection of NOPASSWD ALL rules, providing
immediate root access without credentials.
"@
            fncSubmitFinding `
                -Id ("SUDO-" + (fncShortHashTag "SUDOERS_PERMS")) `
                -Title "sudoers File Has Incorrect Permissions" `
                -Category "Privilege Escalation Prevention" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("/etc/sudoers has permissions $perms (expected 440). Incorrect permissions risk privilege map disclosure or tampering.") `
                -Recommendation "Restore correct permissions: sudo chmod 440 /etc/sudoers" `
                -Evidence @("/etc/sudoers permissions = $perms") `
                -SourceTests @($testId) `
                -Exploitation $exploitation `
                -Remediation "Run: sudo chmod 440 /etc/sudoers`nVerify: sudo visudo -c"

        }
        else {
            fncTestMessage "/etc/sudoers permissions = $perms [OK]" "proten"
        }

    }
    catch {}

    Write-Host ""

    # ----------------------------------------------------------------
    # Collect all sudoers files to scan
    # ----------------------------------------------------------------
    $sudoersFiles = [System.Collections.Generic.List[string]]::new()
    $sudoersFiles.Add($sudoersPath)

    if (Test-Path $sudoersDDir) {
        Get-ChildItem $sudoersDDir -File -ErrorAction SilentlyContinue |
            ForEach-Object { $sudoersFiles.Add($_.FullName) }
    }

    # ----------------------------------------------------------------
    # NOPASSWD entries
    # ----------------------------------------------------------------
    fncTestMessage "Checking for NOPASSWD sudo entries..." "info"

    $noPasswdEntries = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $sudoersFiles) {
        try {
            Get-Content $file -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'NOPASSWD' } |
                ForEach-Object { $noPasswdEntries.Add(("{0} : {1}" -f $file, $_.Trim())) }
        }
        catch {}
    }

    if ($noPasswdEntries.Count -gt 0) {

        $exploitation = @"
NOPASSWD sudo entries allow privilege escalation to root without any credential requirement.
If the user account is compromised (e.g. via web shell, SSRF, or stolen session), the
attacker gains root access immediately without knowing any password.

Cross-reference entries against GTFOBins: https://gtfobins.github.io/
"@
        $remediation = @"
Review each NOPASSWD entry with: sudo visudo

Replace broad NOPASSWD rules with specific, path-restricted commands:

    # Instead of:
    user ALL=(ALL) NOPASSWD: ALL

    # Prefer:
    user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myservice

Remove entries entirely where NOPASSWD is not operationally justified.
"@
        fncSubmitFinding `
            -Id ("SUDO-" + (fncShortHashTag "NOPASSWD_ENTRIES")) `
            -Title "Sudo NOPASSWD Entries Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("$($noPasswdEntries.Count) NOPASSWD sudo entry(s) found. Affected accounts can escalate to root without credentials.") `
            -Recommendation "Remove or scope NOPASSWD entries to specific commands in sudoers." `
            -Evidence $noPasswdEntries.ToArray() `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation $remediation

    }
    else {
        fncTestMessage "No NOPASSWD entries found [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Unrestricted ALL=(ALL) ALL for non-root principals
    # ----------------------------------------------------------------
    fncTestMessage "Checking for unrestricted ALL=(ALL) ALL entries..." "info"

    $wildcardEntries = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $sudoersFiles) {
        try {
            Get-Content $file -ErrorAction SilentlyContinue |
                Where-Object {
                    $_ -notmatch '^\s*#' -and
                    $_ -match 'ALL\s*=\s*\(ALL(:ALL)?\)\s*(NOPASSWD:\s*)?ALL' -and
                    $_ -notmatch '^\s*%?root\b'
                } |
                ForEach-Object { $wildcardEntries.Add(("{0} : {1}" -f $file, $_.Trim())) }
        }
        catch {}
    }

    if ($wildcardEntries.Count -gt 0) {

        $exploitation = @"
Broad ALL=(ALL) ALL grants allow any GTFOBin to be leveraged for root access.
Common escalation paths: sudo vim, sudo python3, sudo find, sudo less, sudo bash.

Reference: https://gtfobins.github.io/
"@
        fncSubmitFinding `
            -Id ("SUDO-" + (fncShortHashTag "WILDCARD_SUDO")) `
            -Title "Unrestricted sudo ALL Privileges Assigned" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$($wildcardEntries.Count) unrestricted ALL=(ALL) ALL sudo entry(s) found. These provide full root access via any sudo-capable binary.") `
            -Recommendation "Scope sudo entries to explicit command paths rather than ALL. Audit against GTFOBins." `
            -Evidence $wildcardEntries.ToArray() `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation "Edit sudoers via 'sudo visudo' and replace ALL with specific absolute command paths."

    }
    else {
        fncTestMessage "No unrestricted ALL=(ALL) ALL entries found [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # World-writable files in /etc/sudoers.d
    # ----------------------------------------------------------------
    if (Test-Path $sudoersDDir) {

        fncTestMessage "Checking /etc/sudoers.d for world-writable files..." "info"

        try {

            $wwRaw = (& bash -c "find /etc/sudoers.d -maxdepth 1 -type f -perm -o=w 2>/dev/null").Trim()

            if ($wwRaw) {

                $wwFiles = $wwRaw -split "`n" | Where-Object { $_ }

                fncSubmitFinding `
                    -Id ("SUDO-" + (fncShortHashTag "SUDOERSD_WRITABLE")) `
                    -Title "World-Writable File in /etc/sudoers.d" `
                    -Category "Privilege Escalation Prevention" `
                    -Severity "Critical" `
                    -Status "Detected" `
                    -Message ("$($wwFiles.Count) world-writable file(s) found in /etc/sudoers.d. Any local user can inject sudo rules to gain root.") `
                    -Recommendation "Remove world-write permission: sudo chmod o-w /etc/sudoers.d/*" `
                    -Evidence $wwFiles `
                    -SourceTests @($testId) `
                    -Exploitation "A local user can append 'username ALL=(ALL) NOPASSWD: ALL' to a world-writable sudoers.d file and immediately gain root without a password." `
                    -Remediation "Run: sudo chmod 440 /etc/sudoers.d/*`nAudit for unexpected files: ls -la /etc/sudoers.d/"

            }
            else {
                fncTestMessage "No world-writable files in /etc/sudoers.d [OK]" "proten"
            }

        }
        catch {}
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Sudo version - CVE-2021-3156 (Baron Samedit)
    # ----------------------------------------------------------------
    fncTestMessage "Checking sudo version..." "info"

    try {

        $sudoVerLine = (& bash -c "sudo -V 2>/dev/null | head -1").Trim()

        if ($sudoVerLine -match "Sudo version\s+(\S+)") {

            $ver = $matches[1]
            fncTestMessage "Sudo version: $ver" "info"

            # CVE-2021-3156 affects 1.8.2 through 1.9.5p1
            if ($ver -match '^1\.(8\.[2-9]|8\.[1-9]\d|9\.[0-4]\.|9\.5p[01]$)') {

                $exploitation = @"
CVE-2021-3156 (Baron Samedit) is a heap-based buffer overflow in sudo affecting
versions 1.8.2 through 1.9.5p1. It allows any local user - including those
not listed in sudoers - to gain root privileges without authentication.

Public exploits are widely available for major Linux distributions.
CVSS v3 score: 7.8 (High)
"@
                fncSubmitFinding `
                    -Id ("SUDO-" + (fncShortHashTag "CVE_2021_3156")) `
                    -Title "Sudo Potentially Vulnerable to CVE-2021-3156 (Baron Samedit)" `
                    -Category "Privilege Escalation Prevention" `
                    -Severity "Critical" `
                    -Status "Detected" `
                    -Message ("Sudo version $ver may be vulnerable to CVE-2021-3156 - heap overflow allowing unauthenticated local root escalation.") `
                    -Recommendation "Upgrade sudo to 1.9.5p2 or later using the system package manager." `
                    -Evidence @("Sudo version = $ver", "Vulnerable range: 1.8.2 - 1.9.5p1") `
                    -SourceTests @($testId) `
                    -Exploitation $exploitation `
                    -Remediation "Debian/Ubuntu: sudo apt update && sudo apt install sudo`nRHEL/CentOS: sudo yum update sudo`nVerify: sudo -V"

            }
            else {
                fncTestMessage "Sudo version $ver - no known critical CVEs matched [OK]" "proten"
            }
        }

    }
    catch {}

    Write-Host ""

    # ----------------------------------------------------------------
    # sudo log file configured (CIS 5.3.3)
    # ----------------------------------------------------------------
    fncTestMessage "Checking for sudo log file configuration..." "info"

    $hasLogfile = $false

    foreach ($file in $sudoersFiles) {
        try {
            $logMatch = Get-Content $file -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'Defaults\s+logfile' } |
                Select-Object -First 1
            if ($logMatch) { $hasLogfile = $true; break }
        }
        catch {}
    }

    if (-not $hasLogfile) {

        fncSubmitFinding `
            -Id ("SUDO-" + (fncShortHashTag "NO_LOGFILE")) `
            -Title "Sudo Log File Not Configured" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "No 'Defaults logfile' entry found in sudoers. Sudo activity is logged only to syslog/journald which may be overwritten or excluded from SIEM ingestion." `
            -Recommendation "Add a dedicated sudo log file in /etc/sudoers: Defaults logfile=/var/log/sudo.log" `
            -Evidence @("No 'Defaults logfile' directive found in sudoers or sudoers.d") `
            -SourceTests @($testId) `
            -Remediation "Add to /etc/sudoers via visudo:`n    Defaults logfile=/var/log/sudo.log`nEnsure log rotation: add /var/log/sudo.log to /etc/logrotate.d/"

    }
    else {
        fncTestMessage "Sudo logfile directive found [OK]" "proten"
    }

    Write-Host ""
    fncTestMessage "Sudo configuration assessment complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxSudoConfig", "fncGetMappings_LINUX_SUDO_CONFIG")
