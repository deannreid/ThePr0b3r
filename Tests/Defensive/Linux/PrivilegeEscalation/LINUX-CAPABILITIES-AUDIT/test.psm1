# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1548";     Name = "Abuse Elevation Control Mechanism";      Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1548/" }
        [pscustomobject]@{ Id = "T1068";     Name = "Exploitation for Privilege Escalation";  Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1068/" }
        [pscustomobject]@{ Id = "T1574.006"; Name = "Hijack Execution Flow: Dynamic Linker Hijacking"; Tactic = "Privilege Escalation"; Url = "https://attack.mitre.org/techniques/T1574/006/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-250"; Name = "Execution with Unnecessary Privileges"; Url = "https://cwe.mitre.org/data/definitions/250.html" }
        [pscustomobject]@{ Id = "CWE-272"; Name = "Least Privilege Violation";             Url = "https://cwe.mitre.org/data/definitions/272.html" }
        [pscustomobject]@{ Id = "CWE-269"; Name = "Improper Privilege Management";         Url = "https://cwe.mitre.org/data/definitions/269.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-6";  Name = "Least Privilege";         Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings";  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-7";  Name = "Least Functionality";     Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "5.4"; Name = "Ensure setuid programs do not create world writable files"; Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Capabilities assigned to binaries should be reviewed and restricted to operationally required minimums." }
    )
}

function fncGetMappings_LINUX_CAPABILITIES_AUDIT { return $script:Mappings }

# ----------------------------------------------------------------
# Capability severity and remediation database
# ----------------------------------------------------------------
$script:CapDb = [ordered]@{
    "cap_setuid"          = @{ Severity = "Critical"; Reason = "Allows calling setuid(0) to become root. Any language runtime or interpreter with this capability provides direct root shell access." }
    "cap_setgid"          = @{ Severity = "Critical"; Reason = "Allows calling setgid(0) to gain root group. Combined with cap_setuid provides full root." }
    "cap_sys_admin"       = @{ Severity = "Critical"; Reason = "Encompasses ~25 privilege operations: mount, namespace creation, kernel keyring, device configuration, hostname. Near-equivalent to root." }
    "cap_sys_module"      = @{ Severity = "Critical"; Reason = "Allows loading and unloading kernel modules. Equivalent to arbitrary kernel code execution (ring 0)." }
    "cap_dac_override"    = @{ Severity = "High";     Reason = "Bypasses all discretionary access control checks for read, write, and execute on any file regardless of ownership or permissions." }
    "cap_dac_read_search" = @{ Severity = "High";     Reason = "Bypasses read and search permission checks. Allows reading any file including /etc/shadow and private keys." }
    "cap_sys_ptrace"      = @{ Severity = "High";     Reason = "Allows attaching to and tracing any process, including processes owned by root. Enables credential extraction and code injection." }
    "cap_chown"           = @{ Severity = "High";     Reason = "Allows changing ownership of any file. An attacker can take ownership of /etc/shadow or SUID binaries." }
    "cap_fowner"          = @{ Severity = "High";     Reason = "Bypasses ownership-based permission checks. Allows chmod on files the process does not own." }
    "cap_sys_rawio"       = @{ Severity = "High";     Reason = "Allows raw I/O access via /dev/mem, /dev/port, and /proc/kcore. Enables reading physical memory for credential extraction." }
    "cap_setfcap"         = @{ Severity = "High";     Reason = "Allows setting file capabilities on any file. Can be used to grant cap_setuid to any binary for subsequent root escalation." }
    "cap_setpcap"         = @{ Severity = "Medium";   Reason = "Allows transferring or removing capabilities from own capability set and setting capabilities in permitted set of child processes." }
    "cap_net_admin"       = @{ Severity = "Medium";   Reason = "Full network administration: modify interfaces, routing tables, firewall rules, ARP entries, and perform traffic shaping." }
    "cap_net_raw"         = @{ Severity = "Medium";   Reason = "Allows creating raw sockets and packet sockets. Enables network sniffing and packet crafting/spoofing." }
    "cap_bpf"             = @{ Severity = "Medium";   Reason = "Allows creating privileged BPF maps and programs. May enable kernel memory access on older kernels with weak verifier." }
    "cap_sys_chroot"      = @{ Severity = "Low";      Reason = "Allows using chroot to change root directory. Combined with host filesystem mounts can escape container boundaries." }
    "cap_kill"            = @{ Severity = "Low";      Reason = "Allows sending signals to any process regardless of UID. Can terminate security daemons or trigger signal handlers." }
    "cap_linux_immutable" = @{ Severity = "Low";      Reason = "Allows setting and clearing the immutable and append-only flags on files. Can prevent log tampering detection." }
}

# ================================================================
# Function: fncCheckLinuxCapabilitiesAudit
# ================================================================
function fncCheckLinuxCapabilitiesAudit {

    fncSafeSectionHeader "Linux File Capabilities Security Audit"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only: runs getcap -r / to enumerate file capabilities. No capabilities are modified."
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Enumerating file capabilities across filesystem (this may take 30-60 seconds)..." "info"
    Write-Host ""

    $testId = "LINUX-CAPABILITIES-AUDIT"

    # Check getcap is available
    $getcapPath = (& bash -c "which getcap 2>/dev/null").Trim()
    if (-not $getcapPath) {
        fncTestMessage "getcap not found. Install libcap2-bin: apt install libcap2-bin" "warning"
        return
    }

    # Run getcap across entire filesystem
    $raw = @()
    try {
        $raw = @((& bash -c "getcap -r / 2>/dev/null") -split "`n" | Where-Object { $_ -match '=' })
    } catch {
        fncTestMessage ("getcap enumeration failed: {0}" -f $_.Exception.Message) "warning"
        return
    }

    fncTestMessage ("{0} files with capabilities found. Analysing..." -f $raw.Count) "info"
    Write-Host ""

    if ($raw.Count -eq 0) {
        fncTestMessage "No files with capabilities found [OK]" "proten"
        Write-Host ""
        return
    }

    # Parse each getcap line and categorise
    $byFile = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($line in $raw) {
        # Format: /path/to/binary = cap_name+ep[,cap_name+ep...]
        if ($line -notmatch '^(\S+)\s*=\s*(.+)$') { continue }
        $filePath = $Matches[1]
        $capsStr  = $Matches[2]

        # Extract all cap_xxx names from the capability string
        $capNames = [regex]::Matches($capsStr, 'cap_[a-z_]+') | ForEach-Object { $_.Value.ToLower() }

        $highestSeverity = "Info"
        $matchedCaps     = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($cap in $capNames) {
            if ($script:CapDb.Contains($cap)) {
                $entry = $script:CapDb[$cap]
                $matchedCaps.Add([pscustomobject]@{ Cap = $cap; Severity = $entry.Severity; Reason = $entry.Reason })
                # Track highest severity
                $order = @{ "Critical" = 4; "High" = 3; "Medium" = 2; "Low" = 1; "Info" = 0 }
                if ($order[$entry.Severity] -gt $order[$highestSeverity]) {
                    $highestSeverity = $entry.Severity
                }
            }
        }

        if ($matchedCaps.Count -gt 0) {
            $byFile.Add([pscustomobject]@{
                Path             = $filePath
                CapsStr          = $capsStr
                MatchedCaps      = $matchedCaps
                HighestSeverity  = $highestSeverity
            })
        }
    }

    if ($byFile.Count -eq 0) {
        fncTestMessage "No dangerous capabilities found on any files [OK]" "proten"
        Write-Host ""
        return
    }

    # Report Critical capabilities
    $critical = @($byFile | Where-Object { $_.HighestSeverity -eq "Critical" })
    if ($critical.Count -gt 0) {
        fncTestMessage ("Found {0} file(s) with CRITICAL capabilities:" -f $critical.Count) "warning"
        $critEvidence = $critical | ForEach-Object {
            $capList = ($_.MatchedCaps | Where-Object { $_.Severity -eq "Critical" } | ForEach-Object { $_.Cap }) -join ", "
            "{0}  [{1}]  caps: {2}" -f $_.Path, $_.HighestSeverity, $_.CapsStr
        }
        fncSubmitFinding `
            -Id ("CAP-" + (fncShortHashTag "CRITICAL_CAPS")) `
            -Title "Critical File Capabilities Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("$($critical.Count) file(s) have critical capabilities (cap_setuid / cap_setgid / cap_sys_admin / cap_sys_module). Any of these can be leveraged for direct root escalation by any user who can execute the binary.") `
            -Recommendation "Remove capabilities not operationally required: setcap -r /path/to/binary. Review all entries and justify each." `
            -Evidence $critEvidence `
            -SourceTests @($testId) `
            -Exploitation "cap_setuid: python3 -c 'import os; os.setuid(0); os.execl(`"/bin/bash`", `"bash`")'`ncap_sys_admin: nsenter --mount=/proc/1/ns/mnt -- /bin/bash (container escape)`ncap_sys_module: insmod /path/to/rootkit.ko`nRun LINUX-PRIVESC-CAPABILITIES for per-binary exploitation commands." `
            -Remediation "Remove: setcap -r /path/to/binary`nVerify removal: getcap /path/to/binary (should return nothing)`nAudit all caps periodically: getcap -r / 2>/dev/null"
        Write-Host ""
    }

    # Report High capabilities
    $high = @($byFile | Where-Object { $_.HighestSeverity -eq "High" })
    if ($high.Count -gt 0) {
        $highEvidence = $high | ForEach-Object { "{0}  [{1}]  caps: {2}" -f $_.Path, $_.HighestSeverity, $_.CapsStr }
        fncSubmitFinding `
            -Id ("CAP-" + (fncShortHashTag "HIGH_CAPS")) `
            -Title "High-Severity File Capabilities Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("$($high.Count) file(s) have high-severity capabilities (cap_dac_override / cap_dac_read_search / cap_sys_ptrace / cap_chown / cap_fowner / cap_sys_rawio / cap_setfcap). These allow reading/writing arbitrary files or injecting into root processes.") `
            -Recommendation "Review each binary. Remove capabilities not required for the specific operation: setcap -r /path/to/binary" `
            -Evidence $highEvidence `
            -SourceTests @($testId) `
            -Exploitation "cap_dac_read_search: cat /etc/shadow (with a binary that has this cap)`ncap_dac_override: echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd`ncap_sys_ptrace: attach gdb to root process for code injection" `
            -Remediation "setcap -r /path/to/binary`nIf capability is required, scope it to the minimal required capability."
        Write-Host ""
    }

    # Report Medium capabilities
    $medium = @($byFile | Where-Object { $_.HighestSeverity -eq "Medium" })
    if ($medium.Count -gt 0) {
        $medEvidence = $medium | ForEach-Object { "{0}  [{1}]  caps: {2}" -f $_.Path, $_.HighestSeverity, $_.CapsStr }
        fncSubmitFinding `
            -Id ("CAP-" + (fncShortHashTag "MEDIUM_CAPS")) `
            -Title "Medium-Severity File Capabilities Detected" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$($medium.Count) file(s) have medium-severity capabilities (cap_net_admin / cap_net_raw / cap_setpcap / cap_bpf). These allow network manipulation, packet capture, or capability propagation.") `
            -Recommendation "Review each binary. cap_net_bind_service is acceptable for services needing port 80/443. Others should be justified and minimised." `
            -Evidence $medEvidence `
            -SourceTests @($testId) `
            -Remediation "setcap -r /path/to/binary (to remove all caps)`nOr restrict to specific type: setcap cap_net_bind_service+ep /path/to/binary"
        Write-Host ""
    }

    # Report Low capabilities (informational)
    $low = @($byFile | Where-Object { $_.HighestSeverity -eq "Low" })
    if ($low.Count -gt 0) {
        $lowEvidence = $low | ForEach-Object { "{0}  caps: {1}" -f $_.Path, $_.CapsStr }
        fncSubmitFinding `
            -Id ("CAP-" + (fncShortHashTag "LOW_CAPS")) `
            -Title "Low-Severity File Capabilities Present" `
            -Category "Privilege Escalation Prevention" `
            -Severity "Low" `
            -Status "Detected" `
            -Message ("$($low.Count) file(s) have low-severity capabilities (cap_sys_chroot / cap_kill / cap_linux_immutable). Review to confirm operational requirement.") `
            -Recommendation "Verify each binary requires this capability for normal operation. Remove if not justified." `
            -Evidence $lowEvidence `
            -SourceTests @($testId) `
            -Remediation "setcap -r /path/to/binary"
        Write-Host ""
    }

    fncTestMessage ("Capability audit complete. {0} file(s) with dangerous capabilities found." -f $byFile.Count) "info"
}

Export-ModuleMember -Function @("fncCheckLinuxCapabilitiesAudit", "fncGetMappings_LINUX_CAPABILITIES_AUDIT")
