# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1548.001"; Name = "Abuse Elevation Control Mechanism: Setuid and Setgid"; Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1548/001/" }
        [pscustomobject]@{ Id = "T1059";     Name = "Command and Scripting Interpreter";                    Tactic = "Execution";            Url = "https://attack.mitre.org/techniques/T1059/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-250"; Name = "Execution with Unnecessary Privileges";             Url = "https://cwe.mitre.org/data/definitions/250.html" }
        [pscustomobject]@{ Id = "CWE-272"; Name = "Least Privilege Violation";                         Url = "https://cwe.mitre.org/data/definitions/272.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6";  Name = "Least Privilege";         Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings";  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-7";  Name = "Least Functionality";     Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "6.1.13"; Name = "Audit SUID executables"; Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "SUID and SGID binaries not required for system operation should be removed or have the bit cleared." }
    )
}

function fncGetMappings_LINUX_SUID_SGID_AUDIT { return $script:Mappings }

# Known-safe SUID baseline - commonly expected on standard Linux installs
$script:SafeSuidBaseline = @(
    "passwd", "sudo", "su", "newgrp", "chfn", "chsh", "gpasswd",
    "mount", "umount", "pkexec", "ping", "ping6", "ping4",
    "unix_chkpwd", "ssh-keysign", "dbus-daemon-launch-helper",
    "fusermount", "fusermount3", "newuidmap", "newgidmap",
    "at", "crontab", "write", "wall", "expiry", "chage",
    "pt_chown", "pam_timestamp_check", "unix2_chkpwd",
    "polkit-agent-helper-1", "suexec", "postqueue", "postdrop",
    "ksu", "ssh-agent", "sg", "chroot", "traceroute", "traceroute6"
)

# GTFOBins binaries with known SUID escalation paths
$script:GtfoBinsSuid = @(
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python2.7", "python3",
    "perl", "perl5", "ruby", "lua", "node", "nodejs", "php",
    "awk", "gawk", "mawk", "nawk",
    "find", "nmap", "vim", "vi", "nano", "pico", "emacs", "ed",
    "more", "less", "man", "most", "pg",
    "cp", "mv", "dd", "tee", "cat", "head", "tail",
    "tar", "zip", "unzip", "7z", "gzip", "gunzip",
    "wget", "curl", "nc", "ncat", "netcat", "socat",
    "strace", "ltrace", "gdb",
    "base64", "xxd", "od", "hexdump",
    "env", "nice", "nohup", "taskset", "timeout", "time",
    "watch", "xargs", "rlwrap", "script", "screen",
    "docker", "podman", "lxc",
    "systemctl", "journalctl", "dmesg"
)

# ================================================================
# Function: fncCheckLinuxSuidSgid
# ================================================================
function fncCheckLinuxSuidSgid {

    fncSafeSectionHeader "SUID/SGID Binary Audit"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only filesystem enumeration via find - no privilege operations performed"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Enumerating SUID and SGID binaries across the filesystem..." "info"
    fncTestMessage "This may take 30-60 seconds on large filesystems." "info"
    Write-Host ""

    $testId = "LINUX-SUID-SGID-AUDIT"

    # ----------------------------------------------------------------
    # Enumerate SUID binaries
    # ----------------------------------------------------------------
    $suidRaw = @()
    try {
        $suidRaw = @((& bash -c "find / -xdev -perm -4000 -type f 2>/dev/null") -split "`n" | Where-Object { $_ })
    }
    catch {
        fncTestMessage ("SUID enumeration failed: {0}" -f $_.Exception.Message) "warning"
    }

    # ----------------------------------------------------------------
    # Enumerate SGID binaries
    # ----------------------------------------------------------------
    $sgidRaw = @()
    try {
        $sgidRaw = @((& bash -c "find / -xdev -perm -2000 -type f 2>/dev/null") -split "`n" | Where-Object { $_ })
    }
    catch {
        fncTestMessage ("SGID enumeration failed: {0}" -f $_.Exception.Message) "warning"
    }

    fncTestMessage ("Found {0} SUID and {1} SGID binaries." -f $suidRaw.Count, $sgidRaw.Count) "info"
    Write-Host ""

    # ----------------------------------------------------------------
    # Analyse SUID - compare against baseline and GTFOBins
    # ----------------------------------------------------------------
    fncTestMessage "Checking SUID binaries against baseline and GTFOBins database..." "info"
    Write-Host ""

    $nonBaselineSuid = [System.Collections.Generic.List[string]]::new()
    $gtfoBinMatches  = [System.Collections.Generic.List[string]]::new()

    foreach ($path in $suidRaw) {

        $name = [System.IO.Path]::GetFileName($path).ToLower()

        $inBaseline = $script:SafeSuidBaseline | Where-Object { $_.ToLower() -eq $name }

        if (-not $inBaseline) {

            $nonBaselineSuid.Add($path)

            # Strip version suffixes for GTFOBins matching (python3.11 -> python3 -> python)
            $stripped1 = $name -replace '\.\d+(\.\d+)*$', ''
            $stripped2 = $name -replace '\d+(\.\d+)*$', ''

            $isGtfo = $script:GtfoBinsSuid | Where-Object {
                $name -eq $_ -or $stripped1 -eq $_ -or $stripped2 -eq $_
            }

            if ($isGtfo) {
                $gtfoBinMatches.Add($path)
            }
        }
    }

    if ($nonBaselineSuid.Count -gt 0) {

        fncSubmitFinding `
            -Id ("SUID-" + (fncShortHashTag "NON_BASELINE_SUID")) `
            -Title "Non-Baseline SUID Binaries Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$($nonBaselineSuid.Count) SUID binary(s) not in the known-safe baseline. Each represents a potential privilege escalation vector.") `
            -Recommendation "Review each binary. Remove the SUID bit from any not operationally required: sudo chmod u-s /path/to/binary" `
            -Evidence $nonBaselineSuid.ToArray() `
            -SourceTests @($testId) `
            -Exploitation "Any SUID binary executing as root can be leveraged to escalate privileges if it allows arbitrary code execution, file access, or shell escape. Cross-reference: https://gtfobins.github.io/" `
            -Remediation "For each unnecessary SUID binary:`n    sudo chmod u-s /path/to/binary`nVerify: find / -xdev -perm -4000 -type f 2>/dev/null"
    }
    else {
        fncTestMessage "All SUID binaries match the known-safe baseline [OK]" "proten"
    }

    Write-Host ""

    if ($gtfoBinMatches.Count -gt 0) {

        fncSubmitFinding `
            -Id ("SUID-" + (fncShortHashTag "GTFOBINS_SUID")) `
            -Title "GTFOBins-Listed SUID Binaries Present" `
            -Category "Privilege Escalation Prevention" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("$($gtfoBinMatches.Count) SUID binary(s) match known GTFOBins escalation patterns. These can be used to obtain a root shell directly.") `
            -Recommendation "Remove the SUID bit from all listed binaries not required for system operation." `
            -Evidence $gtfoBinMatches.ToArray() `
            -SourceTests @($testId) `
            -Exploitation "GTFOBins SUID binaries provide direct local root escalation with no additional prerequisites. Run LINUX-PRIVESC-SUID for per-binary escalation commands." `
            -Remediation "Remove SUID bit: sudo chmod u-s /path/to/binary`nReference: https://gtfobins.github.io/"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Analyse SGID - flag non-standard entries
    # ----------------------------------------------------------------
    fncTestMessage "Checking SGID binaries against baseline..." "info"
    Write-Host ""

    $sgidBaseline = @(
        "wall", "write", "ssh-agent", "crontab", "at", "locate",
        "mlocate", "plocate", "chage", "expiry", "dotlockfile",
        "mail", "mailx", "sendmail", "postdrop", "postqueue",
        "procmail", "utmp", "screen"
    )

    $nonBaselineSgid = [System.Collections.Generic.List[string]]::new()

    foreach ($path in $sgidRaw) {
        $name = [System.IO.Path]::GetFileName($path).ToLower()
        if (-not ($sgidBaseline | Where-Object { $_.ToLower() -eq $name })) {
            $nonBaselineSgid.Add($path)
        }
    }

    if ($nonBaselineSgid.Count -gt 0) {

        fncSubmitFinding `
            -Id ("SUID-" + (fncShortHashTag "NON_BASELINE_SGID")) `
            -Title "Non-Baseline SGID Binaries Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Low" `
            -Status "Detected" `
            -Message ("$($nonBaselineSgid.Count) SGID binary(s) not in the known-safe baseline. SGID binaries execute with group owner permissions and may allow group-level privilege escalation.") `
            -Recommendation "Review each SGID binary and remove the bit if not required: sudo chmod g-s /path/to/binary" `
            -Evidence $nonBaselineSgid.ToArray() `
            -SourceTests @($testId) `
            -Remediation "Remove SGID bit: sudo chmod g-s /path/to/binary`nAudit associated group memberships."
    }
    else {
        fncTestMessage "SGID binaries within expected baseline [OK]" "proten"
    }

    Write-Host ""
    fncTestMessage "SUID/SGID audit complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxSuidSgid", "fncGetMappings_LINUX_SUID_SGID_AUDIT")
