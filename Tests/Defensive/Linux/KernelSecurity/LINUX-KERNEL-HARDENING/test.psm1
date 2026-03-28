# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1068"; Name = "Exploitation for Privilege Escalation"; Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1068/" }
        [pscustomobject]@{ Id = "T1055"; Name = "Process Injection";                     Tactic = "Defense Evasion";     Url = "https://attack.mitre.org/techniques/T1055/" }
        [pscustomobject]@{ Id = "T1082"; Name = "System Information Discovery";          Tactic = "Discovery";           Url = "https://attack.mitre.org/techniques/T1082/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-693"; Name = "Protection Mechanism Failure";            Url = "https://cwe.mitre.org/data/definitions/693.html" }
        [pscustomobject]@{ Id = "CWE-668"; Name = "Exposure of Resource to Wrong Sphere";   Url = "https://cwe.mitre.org/data/definitions/668.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SI-16"; Name = "Memory Protection";      Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SC-39"; Name = "Process Isolation";      Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "3.3.1"; Name = "Ensure source routed packets are not accepted";  Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "" }
        [pscustomobject]@{ Id = "3.3.2"; Name = "Ensure ICMP redirects are not accepted";         Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "" }
        [pscustomobject]@{ Id = "3.3.4"; Name = "Ensure suspicious packets are logged";           Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "" }
    )
}

function fncGetMappings_LINUX_KERNEL_HARDENING { return $script:Mappings }

# ----------------------------------------------------------------
# Parameter definitions: name, acceptable values, severity, description, remediation
# ----------------------------------------------------------------
$script:KernelParams = @(
    [pscustomobject]@{
        Param       = "kernel.randomize_va_space"
        Expected    = @("2")
        Severity    = "High"
        Description = "ASLR not fully enabled. Address Space Layout Randomisation should be 2 (full) to make heap and stack spray attacks significantly harder."
        Remediation = "sysctl -w kernel.randomize_va_space=2`nAdd to /etc/sysctl.d/99-hardening.conf: kernel.randomize_va_space = 2"
    }
    [pscustomobject]@{
        Param       = "kernel.dmesg_restrict"
        Expected    = @("1")
        Severity    = "Medium"
        Description = "dmesg output accessible to unprivileged users. Kernel messages may expose memory addresses, device paths, and information useful for exploit development."
        Remediation = "sysctl -w kernel.dmesg_restrict=1`nAdd to /etc/sysctl.d/99-hardening.conf: kernel.dmesg_restrict = 1"
    }
    [pscustomobject]@{
        Param       = "kernel.kptr_restrict"
        Expected    = @("1", "2")
        Severity    = "Medium"
        Description = "Kernel pointer restriction insufficient. Kernel symbol addresses exposed via /proc/kallsyms assist attackers in bypassing KASLR for kernel exploits."
        Remediation = "sysctl -w kernel.kptr_restrict=2`nAdd to /etc/sysctl.d/99-hardening.conf: kernel.kptr_restrict = 2"
    }
    [pscustomobject]@{
        Param       = "kernel.yama.ptrace_scope"
        Expected    = @("1", "2", "3")
        Severity    = "Medium"
        Description = "ptrace is unrestricted (scope=0). Any process can attach to any other process owned by the same user, enabling credential extraction and code injection attacks."
        Remediation = "sysctl -w kernel.yama.ptrace_scope=1`nAdd to /etc/sysctl.d/99-hardening.conf: kernel.yama.ptrace_scope = 1"
    }
    [pscustomobject]@{
        Param       = "fs.protected_hardlinks"
        Expected    = @("1")
        Severity    = "Medium"
        Description = "Hard link protection disabled. Attackers can create hard links to SUID binaries in writable directories to assist privilege escalation via TOCTOU vulnerabilities."
        Remediation = "sysctl -w fs.protected_hardlinks=1`nAdd to /etc/sysctl.d/99-hardening.conf: fs.protected_hardlinks = 1"
    }
    [pscustomobject]@{
        Param       = "fs.protected_symlinks"
        Expected    = @("1")
        Severity    = "Medium"
        Description = "Symlink protection disabled. Attackers can exploit TOCTOU races via symlinks in world-writable sticky directories such as /tmp to overwrite privileged files."
        Remediation = "sysctl -w fs.protected_symlinks=1`nAdd to /etc/sysctl.d/99-hardening.conf: fs.protected_symlinks = 1"
    }
    [pscustomobject]@{
        Param       = "fs.suid_dumpable"
        Expected    = @("0")
        Severity    = "Medium"
        Description = "SUID core dumps permitted. Core dumps of SUID processes may contain sensitive memory including credentials, encryption keys, and session tokens."
        Remediation = "sysctl -w fs.suid_dumpable=0`nAdd to /etc/sysctl.d/99-hardening.conf: fs.suid_dumpable = 0"
    }
    [pscustomobject]@{
        Param       = "net.ipv4.tcp_syncookies"
        Expected    = @("1")
        Severity    = "Medium"
        Description = "TCP SYN cookie protection disabled. Host is vulnerable to TCP SYN flood denial-of-service attacks exhausting the connection table."
        Remediation = "sysctl -w net.ipv4.tcp_syncookies=1`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv4.tcp_syncookies = 1"
    }
    [pscustomobject]@{
        Param       = "net.ipv4.conf.all.rp_filter"
        Expected    = @("1", "2")
        Severity    = "Low"
        Description = "Reverse path filtering disabled on all interfaces. Host may be susceptible to IP address spoofing attacks."
        Remediation = "sysctl -w net.ipv4.conf.all.rp_filter=1`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv4.conf.all.rp_filter = 1"
    }
    [pscustomobject]@{
        Param       = "net.ipv4.conf.all.accept_source_route"
        Expected    = @("0")
        Severity    = "Low"
        Description = "IPv4 source routing accepted. Source-routed packets can bypass network controls and be used to spoof traffic paths."
        Remediation = "sysctl -w net.ipv4.conf.all.accept_source_route=0`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv4.conf.all.accept_source_route = 0"
    }
    [pscustomobject]@{
        Param       = "net.ipv4.conf.all.accept_redirects"
        Expected    = @("0")
        Severity    = "Low"
        Description = "ICMP redirect acceptance enabled. Attackers on the local network can redirect host traffic via forged ICMP redirect messages."
        Remediation = "sysctl -w net.ipv4.conf.all.accept_redirects=0`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv4.conf.all.accept_redirects = 0"
    }
    [pscustomobject]@{
        Param       = "net.ipv4.conf.all.send_redirects"
        Expected    = @("0")
        Severity    = "Low"
        Description = "ICMP redirect sending enabled. This host may assist man-in-the-middle attacks against other hosts on the same subnet."
        Remediation = "sysctl -w net.ipv4.conf.all.send_redirects=0`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv4.conf.all.send_redirects = 0"
    }
    [pscustomobject]@{
        Param       = "net.ipv6.conf.all.accept_redirects"
        Expected    = @("0")
        Severity    = "Low"
        Description = "IPv6 ICMP redirect acceptance enabled. Attackers can redirect IPv6 traffic via forged ICMPv6 redirect messages."
        Remediation = "sysctl -w net.ipv6.conf.all.accept_redirects=0`nAdd to /etc/sysctl.d/99-hardening.conf: net.ipv6.conf.all.accept_redirects = 0"
    }
)

function fncReadSysctl {
    param([string]$Param)
    try {
        $val = (& bash -c "sysctl -n $Param 2>/dev/null").Trim()
        return $val
    }
    catch { return $null }
}

# ================================================================
# Function: fncCheckLinuxKernelHardening
# ================================================================
function fncCheckLinuxKernelHardening {

    fncSafeSectionHeader "Kernel Security Parameter Audit"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only sysctl enumeration - no parameters are modified"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating kernel security sysctl parameters..." "info"
    Write-Host ""

    $testId  = "LINUX-KERNEL-HARDENING"
    $passed  = 0
    $failed  = 0
    $missing = 0

    foreach ($p in $script:KernelParams) {

        $val = fncReadSysctl $p.Param

        if ($null -eq $val -or $val -eq "") {
            $missing++
            fncTestMessage ("{0} = (not present on this kernel)" -f $p.Param) "info"
            Write-Host ""
            continue
        }

        if ($p.Expected -contains $val) {
            $passed++
            fncTestMessage ("{0} = {1} [OK]" -f $p.Param, $val) "proten"
        }
        else {
            $failed++
            fncTestMessage ("{0} = {1} [FAIL - expected: {2}]" -f $p.Param, $val, ($p.Expected -join " or ")) "warning"

            fncSubmitFinding `
                -Id ("KERNEL-" + (fncShortHashTag $p.Param)) `
                -Title ("Insecure Kernel Parameter: {0}" -f $p.Param) `
                -Category "Kernel Hardening" `
                -Severity $p.Severity `
                -Status "Detected" `
                -Message ("{0} = {1} (expected: {2}). {3}" -f $p.Param, $val, ($p.Expected -join " or "), $p.Description) `
                -Recommendation ("Set {0} to {1}." -f $p.Param, $p.Expected[0]) `
                -Evidence @(("{0} = {1}" -f $p.Param, $val)) `
                -SourceTests @($testId) `
                -Remediation $p.Remediation
        }

        Write-Host ""
    }

    fncTestMessage ("Results: {0} passed, {1} failed, {2} not present on this kernel." -f $passed, $failed, $missing) "info"
    Write-Host ""
    fncTestMessage "Kernel hardening assessment complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxKernelHardening", "fncGetMappings_LINUX_KERNEL_HARDENING")
