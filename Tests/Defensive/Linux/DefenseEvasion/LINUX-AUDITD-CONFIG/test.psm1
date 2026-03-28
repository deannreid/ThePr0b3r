# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562.001"; Name = "Impair Defenses: Disable or Modify Tools";          Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/001/" }
        [pscustomobject]@{ Id = "T1562.006"; Name = "Impair Defenses: Indicator Blocking";               Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/006/" }
        [pscustomobject]@{ Id = "T1070.002"; Name = "Indicator Removal: Clear Linux or Mac System Logs"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1070/002/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-778"; Name = "Insufficient Logging";                                   Url = "https://cwe.mitre.org/data/definitions/778.html" }
        [pscustomobject]@{ Id = "CWE-223"; Name = "Omission of Security-relevant Information";              Url = "https://cwe.mitre.org/data/definitions/223.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AU-2";  Name = "Event Logging";              Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-3";  Name = "Content of Audit Records";   Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-9";  Name = "Protection of Audit Information"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-11"; Name = "Audit Record Retention";     Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "4.1.1"; Name = "Ensure auditd is installed";                             Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Install auditd to enable Linux kernel audit subsystem." }
        [pscustomobject]@{ Id = "4.1.2"; Name = "Ensure auditd service is enabled and active";            Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "auditd must be running to record security events." }
        [pscustomobject]@{ Id = "4.1.3"; Name = "Ensure auditing for processes that start prior to auditd is enabled"; Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Add audit=1 to kernel boot parameters." }
        [pscustomobject]@{ Id = "4.1.4"; Name = "Ensure audit_backlog_limit is sufficient";               Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Set audit_backlog_limit=8192 or higher in GRUB." }
    )
}

function fncGetMappings_LINUX_AUDITD_CONFIG { return $script:Mappings }

# ================================================================
# Critical audit rule patterns that should be present
# ================================================================
$script:RequiredRulePatterns = @(
    [pscustomobject]@{
        Name        = "Privileged command execution (sudo/su)"
        Patterns    = @('/usr/bin/sudo', '/bin/su', '/usr/bin/su')
        Description = "Tracks all sudo and su invocations for privilege escalation detection"
        Severity    = "High"
    }
    [pscustomobject]@{
        Name        = "/etc/passwd modifications"
        Patterns    = @('/etc/passwd')
        Description = "Detects changes to the local user database"
        Severity    = "High"
    }
    [pscustomobject]@{
        Name        = "/etc/shadow modifications"
        Patterns    = @('/etc/shadow')
        Description = "Detects changes to the password hash store"
        Severity    = "High"
    }
    [pscustomobject]@{
        Name        = "sudoers modifications"
        Patterns    = @('/etc/sudoers', '/etc/sudoers.d')
        Description = "Detects privilege escalation path changes via sudoers"
        Severity    = "High"
    }
    [pscustomobject]@{
        Name        = "SSH authorized_keys changes"
        Patterns    = @('authorized_keys')
        Description = "Detects persistence via SSH key injection"
        Severity    = "Medium"
    }
    [pscustomobject]@{
        Name        = "Kernel module loading (insmod/modprobe)"
        Patterns    = @('init_module', 'finit_module', 'delete_module', '/sbin/insmod', '/sbin/modprobe', '/sbin/rmmod')
        Description = "Detects rootkit installation via kernel module insertion"
        Severity    = "High"
    }
    [pscustomobject]@{
        Name        = "Crontab modifications"
        Patterns    = @('/etc/cron', '/var/spool/cron')
        Description = "Detects persistence via cron job creation"
        Severity    = "Medium"
    }
    [pscustomobject]@{
        Name        = "SUID/SGID bit changes"
        Patterns    = @('-F perm=6000', '-F perm=4000', 'setuid', 'setgid')
        Description = "Detects creation of new SUID/SGID privilege escalation paths"
        Severity    = "Medium"
    }
)

# ================================================================
# Function: fncCheckLinuxAuditd
# Purpose : Evaluate auditd installation, running state, and rules
# ================================================================
function fncCheckLinuxAuditd {

    fncSafeSectionHeader "Audit Daemon Configuration Assessment"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only inspection of auditd configuration and rules - no changes made"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Assessing audit daemon configuration..." "info"
    Write-Host ""

    $testId = "LINUX-AUDITD-CONFIG"

    # ----------------------------------------------------------------
    # Check auditd is installed
    # ----------------------------------------------------------------
    fncTestMessage "Checking if auditd is installed..." "info"

    $auditdInstalled = $false

    try {
        $which = (& bash -c "which auditd 2>/dev/null || command -v auditd 2>/dev/null").Trim()
        if ($which) { $auditdInstalled = $true }
        else {
            $dpkg = (& bash -c "dpkg -l auditd 2>/dev/null | grep '^ii' | head -1").Trim()
            $rpm  = (& bash -c "rpm -q auditd 2>/dev/null | grep -v 'not installed'").Trim()
            if ($dpkg -or $rpm) { $auditdInstalled = $true }
        }
    }
    catch {}

    if (-not $auditdInstalled) {
        fncSubmitFinding `
            -Id ("LAUD-" + (fncShortHashTag "AUDITD_NOT_INSTALLED")) `
            -Title "auditd Is Not Installed" `
            -Category "Detection Capability" `
            -Severity "High" `
            -Status "Detected" `
            -Message "auditd is not installed. No kernel-level security event logging is active. Privilege escalation, credential access, and persistence events will not be captured." `
            -Recommendation "Install and enable auditd: sudo apt-get install auditd audispd-plugins (Debian/Ubuntu) or sudo yum install audit (RHEL/CentOS)." `
            -Evidence @("auditd binary not found") `
            -SourceTests @($testId) `
            -Exploitation "Without auditd, attackers can escalate privileges, modify sensitive files, and establish persistence with no forensic trail." `
            -Remediation "sudo apt-get install auditd audispd-plugins`nsudo systemctl enable --now auditd`nDeploy a CIS-compliant rule set: https://github.com/Neo23x0/auditd"

        fncTestMessage "Cannot continue audit checks without auditd. Stopping." "warning"
        return
    }

    fncTestMessage "auditd is installed [OK]" "proten"
    Write-Host ""

    # ----------------------------------------------------------------
    # Check auditd is running
    # ----------------------------------------------------------------
    fncTestMessage "Checking if auditd service is running..." "info"

    $auditdRunning = $false

    try {
        $status = (& bash -c "systemctl is-active auditd 2>/dev/null").Trim()
        if ($status -eq "active") { $auditdRunning = $true }
        else {
            $pidCheck = (& bash -c "pgrep -x auditd 2>/dev/null | head -1").Trim()
            if ($pidCheck) { $auditdRunning = $true }
        }
    }
    catch {}

    if (-not $auditdRunning) {
        fncSubmitFinding `
            -Id ("LAUD-" + (fncShortHashTag "AUDITD_NOT_RUNNING")) `
            -Title "auditd Service Is Not Running" `
            -Category "Detection Capability" `
            -Severity "High" `
            -Status "Detected" `
            -Message "auditd is installed but not currently running. Security events are not being recorded." `
            -Recommendation "Enable and start auditd: sudo systemctl enable --now auditd" `
            -Evidence @("auditd service is not active") `
            -SourceTests @($testId) `
            -Exploitation "A stopped auditd is a common early attacker action to prevent forensic evidence capture before lateral movement or privilege escalation." `
            -Remediation "sudo systemctl enable --now auditd`nVerify: systemctl status auditd`nCheck for recent tampering: last | head -20"
    }
    else {
        fncTestMessage "auditd service is running [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Load active audit rules
    # ----------------------------------------------------------------
    fncTestMessage "Loading active audit rules..." "info"

    $activeRules = $null

    try {
        $activeRules = (& bash -c "auditctl -l 2>/dev/null").Trim()
    }
    catch {}

    if (-not $activeRules -or $activeRules -match 'No rules' -or $activeRules -match 'Permission denied') {

        # Try reading rule files directly as fallback
        $ruleFiles = @("/etc/audit/rules.d", "/etc/audit/audit.rules")
        $fileRules = [System.Collections.Generic.List[string]]::new()

        foreach ($path in $ruleFiles) {
            if (Test-Path $path) {
                if ((Get-Item $path).PSIsContainer) {
                    Get-ChildItem $path -Filter "*.rules" -ErrorAction SilentlyContinue | ForEach-Object {
                        $content = Get-Content $_.FullName -ErrorAction SilentlyContinue |
                            Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
                        if ($content) { $fileRules.AddRange([string[]]$content) }
                    }
                }
                else {
                    $content = Get-Content $path -ErrorAction SilentlyContinue |
                        Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
                    if ($content) { $fileRules.AddRange([string[]]$content) }
                }
            }
        }

        if ($fileRules.Count -gt 0) {
            $activeRules = $fileRules -join "`n"
            fncTestMessage ("Using rule files (auditctl -l requires root). Found $($fileRules.Count) rule lines.") "info"
        }
        else {
            fncTestMessage "Cannot read active audit rules (may require root for auditctl -l and no rule files found)." "warning"
            $activeRules = ""
        }
    }
    else {
        $ruleCount = ($activeRules -split "`n" | Where-Object { $_ -match '^\s*-' }).Count
        fncTestMessage ("Active audit rules loaded: $ruleCount rule(s)") "info"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Check for required rule coverage
    # ----------------------------------------------------------------
    fncTestMessage "Checking for required audit rule coverage..." "info"
    Write-Host ""

    $missingRules = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($req in $script:RequiredRulePatterns) {
        $covered = $false
        foreach ($pattern in $req.Patterns) {
            if ($activeRules -match [regex]::Escape($pattern)) {
                $covered = $true
                break
            }
        }

        if ($covered) {
            fncTestMessage ("Rule coverage: $($req.Name) [OK]") "proten"
        }
        else {
            fncTestMessage ("Rule coverage: $($req.Name) [MISSING]") "warning"
            $missingRules.Add($req)
        }
    }

    Write-Host ""

    if ($missingRules.Count -gt 0) {
        $bySeverity = $missingRules | Group-Object Severity

        foreach ($group in $bySeverity) {
            $rules = @($group.Group)
            $evidence = $rules | ForEach-Object { "Missing: $($_.Name) - $($_.Description)" }

            fncSubmitFinding `
                -Id ("LAUD-" + (fncShortHashTag ("MISSING_RULES_" + $group.Name.ToUpper()))) `
                -Title ("Audit Rules Missing: $($group.Name)-Severity Coverage Gaps") `
                -Category "Detection Capability" `
                -Severity $group.Name `
                -Status "Detected" `
                -Message ("$($rules.Count) $($group.Name.ToLower())-severity audit rule category(s) are not configured. Security events in these categories will not be logged.") `
                -Recommendation "Add the missing audit rules to /etc/audit/rules.d/. Consider deploying the Neo23x0 auditd ruleset as a baseline." `
                -Evidence @($evidence) `
                -SourceTests @($testId) `
                -Exploitation "Gaps in audit coverage allow attackers to perform the uncovered actions without generating log entries, eliminating forensic evidence." `
                -Remediation "Add rules to /etc/audit/rules.d/hardening.rules and reload:`n  sudo augenrules --load`nReference ruleset: https://github.com/Neo23x0/auditd/blob/master/audit.rules"
        }
    }

    # ----------------------------------------------------------------
    # Check auditd.conf for log retention and disk_full_action
    # ----------------------------------------------------------------
    fncTestMessage "Checking auditd.conf retention and disk-full settings..." "info"

    $auditdConf = "/etc/audit/auditd.conf"

    if (Test-Path $auditdConf) {

        $confLines = Get-Content $auditdConf -ErrorAction SilentlyContinue |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }

        function GetAuditdSetting ([string[]]$Lines, [string]$Key) {
            $match = $Lines | Where-Object { $_ -match "^\s*$Key\s*=" } | Select-Object -Last 1
            if ($match -and $match -match "=\s*(.+)") { return $matches[1].Trim() }
            return $null
        }

        # max_log_file_action - what happens when log file is full
        $maxLogAction = GetAuditdSetting $confLines "max_log_file_action"
        if (-not $maxLogAction) { $maxLogAction = "ROTATE" }

        if ($maxLogAction -eq "IGNORE") {
            fncSubmitFinding `
                -Id ("LAUD-" + (fncShortHashTag "LOG_FULL_IGNORE")) `
                -Title "Audit Log Full Action Set to IGNORE" `
                -Category "Log Integrity" `
                -Severity "High" `
                -Status "Detected" `
                -Message "max_log_file_action = IGNORE. When audit logs are full, new events will be silently dropped. This is exploitable by filling disk space to eliminate evidence." `
                -Recommendation "Set max_log_file_action = ROTATE in /etc/audit/auditd.conf." `
                -Evidence @("max_log_file_action = $maxLogAction") `
                -SourceTests @($testId) `
                -Exploitation "Fill the disk to consume audit log space, then perform malicious actions that will not be logged." `
                -Remediation "Edit /etc/audit/auditd.conf:`n  max_log_file_action = ROTATE`nsudo systemctl restart auditd"
        }
        else {
            fncTestMessage ("max_log_file_action = $maxLogAction [OK]") "proten"
        }

        # disk_full_action
        $diskFullAction = GetAuditdSetting $confLines "disk_full_action"
        if (-not $diskFullAction) { $diskFullAction = "SUSPEND" }

        if ($diskFullAction -eq "IGNORE") {
            fncSubmitFinding `
                -Id ("LAUD-" + (fncShortHashTag "DISK_FULL_IGNORE")) `
                -Title "Audit Disk Full Action Set to IGNORE" `
                -Category "Log Integrity" `
                -Severity "Medium" `
                -Status "Detected" `
                -Message "disk_full_action = IGNORE. When the disk is full, audit events will be silently discarded." `
                -Recommendation "Set disk_full_action = HALT or SYSLOG in /etc/audit/auditd.conf." `
                -Evidence @("disk_full_action = $diskFullAction") `
                -SourceTests @($testId) `
                -Remediation "Edit /etc/audit/auditd.conf:`n  disk_full_action = SYSLOG`nsudo systemctl restart auditd"
        }
        else {
            fncTestMessage ("disk_full_action = $diskFullAction [OK]") "proten"
        }

        # num_logs (retention file count)
        $numLogs = GetAuditdSetting $confLines "num_logs"
        $numLogsVal = if ($numLogs) { [int]($numLogs -replace '\D', '0') } else { 0 }

        if ($numLogsVal -lt 5 -and $numLogsVal -gt 0) {
            fncSubmitFinding `
                -Id ("LAUD-" + (fncShortHashTag "LOW_LOG_RETENTION")) `
                -Title "Audit Log Retention Count Is Low" `
                -Category "Log Integrity" `
                -Severity "Low" `
                -Status "Detected" `
                -Message "num_logs = $numLogsVal. CIS recommends at least 5 rotated log files to maintain sufficient forensic history." `
                -Recommendation "Set num_logs = 5 or higher in /etc/audit/auditd.conf." `
                -Evidence @("num_logs = $numLogsVal") `
                -SourceTests @($testId) `
                -Remediation "Edit /etc/audit/auditd.conf:`n  num_logs = 5`nsudo systemctl restart auditd"
        }
        elseif ($numLogsVal -ge 5) {
            fncTestMessage ("num_logs = $numLogsVal [OK]") "proten"
        }

    }
    else {
        fncTestMessage "/etc/audit/auditd.conf not found." "warning"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Check if audit rules are immutable (-e 2)
    # ----------------------------------------------------------------
    fncTestMessage "Checking if audit configuration is set to immutable mode (-e 2)..." "info"

    $immutable = $activeRules -match '-e\s+2'

    if ($immutable) {
        fncTestMessage "Audit rules are in immutable mode (-e 2). Rules cannot be modified without reboot [OK]" "proten"
    }
    else {
        fncSubmitFinding `
            -Id ("LAUD-" + (fncShortHashTag "NOT_IMMUTABLE")) `
            -Title "Audit Rules Are Not Set to Immutable Mode" `
            -Category "Log Integrity" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "Audit rules do not include '-e 2' (immutable mode). An attacker with root access can modify or flush audit rules at runtime to eliminate their audit trail." `
            -Recommendation "Add '-e 2' as the last line of your audit rules to prevent runtime modification." `
            -Evidence @("'-e 2' not found in active rules") `
            -SourceTests @($testId) `
            -Exploitation "Root attacker can run: auditctl -e 0 to disable auditing, then perform actions without any log entries." `
            -Remediation "Add to the END of /etc/audit/rules.d/99-finalize.rules:`n  -e 2`nNote: This requires a reboot to change rules after setting immutable mode.`nsudo augenrules --load"
    }

    Write-Host ""
    fncTestMessage "Audit daemon configuration assessment complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxAuditd", "fncGetMappings_LINUX_AUDITD_CONFIG")
