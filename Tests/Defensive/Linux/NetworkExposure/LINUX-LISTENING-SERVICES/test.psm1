# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1049";     Name = "System Network Connections Discovery"; Tactic = "Discovery";      Url = "https://attack.mitre.org/techniques/T1049/" }
        [pscustomobject]@{ Id = "T1021.004"; Name = "Remote Services: SSH";                 Tactic = "Lateral Movement"; Url = "https://attack.mitre.org/techniques/T1021/004/" }
        [pscustomobject]@{ Id = "T1190";     Name = "Exploit Public-Facing Application";    Tactic = "Initial Access";  Url = "https://attack.mitre.org/techniques/T1190/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-319"; Name = "Cleartext Transmission of Sensitive Information"; Url = "https://cwe.mitre.org/data/definitions/319.html" }
        [pscustomobject]@{ Id = "CWE-923"; Name = "Improper Restriction of Communication Channel to Intended Endpoints"; Url = "https://cwe.mitre.org/data/definitions/923.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-7";  Name = "Least Functionality";                  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SC-7";  Name = "Boundary Protection";                  Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AC-17"; Name = "Remote Access";                         Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "2.2.1"; Name = "Ensure xinetd is not installed";        Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Remove xinetd to eliminate legacy inetd service hosting." }
        [pscustomobject]@{ Id = "2.2.4"; Name = "Ensure FTP server is not installed";    Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "FTP transmits credentials in cleartext." }
        [pscustomobject]@{ Id = "2.2.5"; Name = "Ensure Telnet server is not installed"; Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Telnet transmits all data including credentials in cleartext." }
    )
}

function fncGetMappings_LINUX_LISTENING_SERVICES { return $script:Mappings }

# ================================================================
# Known dangerous ports: port -> description
# ================================================================
$script:DangerousPorts = @{
    21   = [pscustomobject]@{ Name = "FTP";          Reason = "Transmits credentials and data in cleartext";                                                 Severity = "High"   }
    23   = [pscustomobject]@{ Name = "Telnet";       Reason = "All traffic including passwords transmitted in cleartext";                                    Severity = "Critical" }
    69   = [pscustomobject]@{ Name = "TFTP";         Reason = "No authentication - any host can read/write files";                                          Severity = "High"   }
    79   = [pscustomobject]@{ Name = "Finger";       Reason = "Discloses user account information to unauthenticated requestors";                           Severity = "Medium" }
    111  = [pscustomobject]@{ Name = "RPCBind";      Reason = "RPC portmapper; enables NFS, NIS enumeration and exploitation";                              Severity = "Medium" }
    512  = [pscustomobject]@{ Name = "rexec";        Reason = "Legacy remote execution with password in cleartext";                                          Severity = "Critical" }
    513  = [pscustomobject]@{ Name = "rlogin";       Reason = "Legacy remote login; trusts .rhosts files for passwordless auth";                            Severity = "Critical" }
    514  = [pscustomobject]@{ Name = "rsh / syslog"; Reason = "rsh: legacy remote shell with .rhosts trust; syslog: UDP log injection if exposed";         Severity = "High"   }
    2049 = [pscustomobject]@{ Name = "NFS";          Reason = "Network File System; misconfigured exports can expose filesystem to untrusted hosts";         Severity = "High"   }
    6000 = [pscustomobject]@{ Name = "X11";          Reason = "X Window System; allows keylogging and screen capture if accessible";                        Severity = "High"   }
    6001 = [pscustomobject]@{ Name = "X11";          Reason = "X Window System display :1";                                                                 Severity = "High"   }
    6002 = [pscustomobject]@{ Name = "X11";          Reason = "X Window System display :2";                                                                 Severity = "High"   }
}

# ================================================================
# Function: fncCheckLinuxListeningServices
# Purpose : Enumerate and audit all listening network services
# ================================================================
function fncCheckLinuxListeningServices {

    fncSafeSectionHeader "Listening Network Services Audit"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only enumeration via ss/netstat - no network connections made"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Enumerating listening network services..." "info"
    Write-Host ""

    $testId = "LINUX-LISTENING-SERVICES"

    # ----------------------------------------------------------------
    # Collect listening sockets via ss (preferred) or netstat fallback
    # ----------------------------------------------------------------
    $rawOutput = $null
    $usedTool  = $null

    try {
        $ssTest = (& bash -c "ss --version 2>/dev/null | head -1").Trim()
        if ($ssTest) {
            $rawOutput = (& bash -c "ss -tlnpu 2>/dev/null").Trim()
            $usedTool  = "ss"
        }
    }
    catch {}

    if (-not $rawOutput) {
        try {
            $rawOutput = (& bash -c "netstat -tlnpu 2>/dev/null").Trim()
            $usedTool  = "netstat"
        }
        catch {}
    }

    if (-not $rawOutput) {
        fncTestMessage "Neither ss nor netstat available. Cannot enumerate listening services." "warning"
        return
    }

    fncTestMessage ("Using tool: $usedTool") "info"
    Write-Host ""

    # ----------------------------------------------------------------
    # Parse into structured objects
    # ----------------------------------------------------------------
    $services = [System.Collections.Generic.List[pscustomobject]]::new()

    $rawOutput -split "`n" | Select-Object -Skip 1 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line) { return }

        # ss format: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        # netstat format: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
        $fields = $line -split '\s+'

        $proto      = $null
        $localAddr  = $null
        $port       = $null
        $process    = $null

        if ($usedTool -eq "ss") {
            # State Recv-Q Send-Q Local:Port Peer:Port [Process]
            if ($fields.Count -ge 5) {
                $proto     = if ($line -match '(?i)udp') { "UDP" } else { "TCP" }
                $localFull = $fields[4]
                if ($localFull -match '^(.+):(\d+)$') {
                    $localAddr = $matches[1]
                    $port      = [int]$matches[2]
                }
                elseif ($localFull -match '^\[(.+)\]:(\d+)$') {
                    $localAddr = $matches[1]
                    $port      = [int]$matches[2]
                }
                if ($fields.Count -ge 6) {
                    $process = ($fields[5..($fields.Count-1)] -join ' ') -replace 'users:\(\("?([^",]+)"?.*', '$1'
                }
            }
        }
        else {
            # netstat: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
            if ($fields.Count -ge 4) {
                $proto     = $fields[0].ToUpper() -replace '\d', ''
                $localFull = $fields[3]
                if ($localFull -match '^(.+):(\d+)$') {
                    $localAddr = $matches[1]
                    $port      = [int]$matches[2]
                }
                if ($fields.Count -ge 7) {
                    $process = $fields[6] -replace '^\d+/', ''
                }
            }
        }

        if ($port -gt 0) {
            $services.Add([pscustomobject]@{
                Proto     = $proto
                Address   = $localAddr
                Port      = $port
                Process   = if ($process) { $process } else { "(unknown)" }
                External  = ($localAddr -eq '0.0.0.0' -or $localAddr -eq '::' -or $localAddr -eq '*')
            })
        }
    }

    if ($services.Count -eq 0) {
        fncTestMessage "No listening services found or output could not be parsed." "warning"
        return
    }

    fncTestMessage ("Found $($services.Count) listening service(s) total.") "info"
    Write-Host ""

    # ----------------------------------------------------------------
    # Flag externally-bound services (0.0.0.0 / ::)
    # ----------------------------------------------------------------
    fncTestMessage "Checking for services bound to all interfaces (0.0.0.0 / ::)..." "info"

    $externalServices = @($services | Where-Object { $_.External })

    if ($externalServices.Count -gt 0) {
        $evidence = $externalServices | ForEach-Object {
            "$($_.Proto) port $($_.Port) on $($_.Address) ($($_.Process))"
        }

        fncSubmitFinding `
            -Id ("LNET-" + (fncShortHashTag "EXTERNAL_BOUND")) `
            -Title "Services Bound to All Network Interfaces" `
            -Category "Network Exposure" `
            -Severity "Informational" `
            -Status "Detected" `
            -Message ("$($externalServices.Count) service(s) are bound to 0.0.0.0 or :: and are reachable from all network interfaces. Review whether each service requires external exposure.") `
            -Recommendation "Bind services to specific IPs (127.0.0.1) where external access is not required. Use a host firewall (ufw/iptables/nftables) to restrict access." `
            -Evidence @($evidence) `
            -SourceTests @($testId) `
            -Exploitation "Each externally bound service increases attack surface. Attackers enumerate open ports as a first step to identify vulnerable services." `
            -Remediation "Restrict bind address in each service's configuration file to 127.0.0.1 where external access is not needed.`nEnforce firewall rules: ufw allow from <trusted_ip> to any port <port>"
    }
    else {
        fncTestMessage "No services bound to all interfaces [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Flag inherently dangerous protocols
    # ----------------------------------------------------------------
    fncTestMessage "Checking for dangerous legacy protocols..." "info"

    $dangerousFound = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($svc in $services) {
        if ($script:DangerousPorts.ContainsKey($svc.Port)) {
            $info = $script:DangerousPorts[$svc.Port]
            $dangerousFound.Add([pscustomobject]@{
                Port     = $svc.Port
                Proto    = $svc.Proto
                Name     = $info.Name
                Reason   = $info.Reason
                Severity = $info.Severity
                Address  = $svc.Address
                Process  = $svc.Process
            })
        }
    }

    if ($dangerousFound.Count -gt 0) {
        foreach ($d in ($dangerousFound | Sort-Object Severity)) {
            fncSubmitFinding `
                -Id ("LNET-" + (fncShortHashTag ("DANGEROUS_PORT_" + $d.Port))) `
                -Title ("Dangerous Service Detected: $($d.Name) on port $($d.Port)") `
                -Category "Network Exposure" `
                -Severity $d.Severity `
                -Status "Detected" `
                -Message ("$($d.Name) is listening on $($d.Proto) port $($d.Port) ($($d.Address)) via process '$($d.Process)'. $($d.Reason).") `
                -Recommendation "Disable $($d.Name) and migrate to a secure alternative (e.g., SSH instead of Telnet/rsh/rlogin, SFTP/SCP instead of FTP)." `
                -Evidence @("$($d.Proto)/$($d.Port) on $($d.Address) - $($d.Name)") `
                -SourceTests @($testId) `
                -Exploitation "$($d.Reason). An attacker on the same network can intercept credentials and data in cleartext." `
                -Remediation "Disable service: sudo systemctl disable --now $($d.Process)`nRemove package if installed: sudo apt-get remove <package> or sudo yum remove <package>`nReplace with SSH-based equivalent."
        }
    }
    else {
        fncTestMessage "No dangerous legacy protocol services found [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Summary table
    # ----------------------------------------------------------------
    fncTestMessage "Listening services summary:" "info"
    Write-Host ""

    $col1 = 7   # PROTO
    $col2 = 22  # ADDRESS:PORT
    $col3 = 20  # PROCESS
    $col4 = 10  # SCOPE

    $header = ("{0,-$col1} {1,-$col2} {2,-$col3} {3,-$col4}" -f "PROTO", "ADDRESS:PORT", "PROCESS", "SCOPE")
    Write-Host $header
    Write-Host ("-" * ($col1 + $col2 + $col3 + $col4 + 3))

    foreach ($svc in ($services | Sort-Object Port)) {
        $scope   = if ($svc.External) { "EXTERNAL" } else { "LOCALHOST" }
        $addrPort = "$($svc.Address):$($svc.Port)"
        $line = ("{0,-$col1} {1,-$col2} {2,-$col3} {3,-$col4}" -f $svc.Proto, $addrPort, $svc.Process, $scope)
        Write-Host $line
    }

    Write-Host ""
    fncTestMessage "Listening services audit complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxListeningServices", "fncGetMappings_LINUX_LISTENING_SERVICES")
