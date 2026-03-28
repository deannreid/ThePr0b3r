# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1021.004"; Name = "Remote Services: SSH"; Tactic = "Lateral Movement"; Url = "https://attack.mitre.org/techniques/T1021/004/" }
        [pscustomobject]@{ Id = "T1110";     Name = "Brute Force";          Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1110/" }
        [pscustomobject]@{ Id = "T1572";     Name = "Protocol Tunneling";   Tactic = "Command and Control"; Url = "https://attack.mitre.org/techniques/T1572/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-287"; Name = "Improper Authentication";              Url = "https://cwe.mitre.org/data/definitions/287.html" }
        [pscustomobject]@{ Id = "CWE-521"; Name = "Weak Password Requirements";           Url = "https://cwe.mitre.org/data/definitions/521.html" }
        [pscustomobject]@{ Id = "CWE-732"; Name = "Incorrect Permission Assignment for Critical Resource"; Url = "https://cwe.mitre.org/data/definitions/732.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AC-17"; Name = "Remote Access";               Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "IA-5";  Name = "Authenticator Management";    Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "CM-6";  Name = "Configuration Settings";      Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SC-8";  Name = "Transmission Confidentiality and Integrity"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "5.2.4";  Name = "Ensure SSH access is limited";                             Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Restrict SSH access to authorised users and groups only." }
        [pscustomobject]@{ Id = "5.2.8";  Name = "Ensure SSH PermitRootLogin is disabled";                   Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Prevent direct root login over SSH to ensure audit trails and accountability." }
        [pscustomobject]@{ Id = "5.2.11"; Name = "Ensure SSH PasswordAuthentication is disabled";            Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Require key-based authentication to eliminate password brute-force exposure." }
        [pscustomobject]@{ Id = "5.2.12"; Name = "Ensure SSH PermitEmptyPasswords is disabled";              Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Prevent accounts with empty passwords from authenticating via SSH." }
        [pscustomobject]@{ Id = "5.2.6";  Name = "Ensure SSH X11 forwarding is disabled";                   Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Disable X11 forwarding to reduce graphical session attack surface." }
        [pscustomobject]@{ Id = "5.2.7";  Name = "Ensure SSH MaxAuthTries is set to 4 or less";             Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Limit authentication attempts per connection to reduce brute-force exposure." }
    )
}

function fncGetMappings_LINUX_SSH_HARDENING { return $script:Mappings }

# ================================================================
# Function: fncCheckLinuxSshHardening
# Purpose : Evaluate sshd_config hardening posture on Linux
# ================================================================
function fncCheckLinuxSshHardening {

    fncSafeSectionHeader "SSH Daemon Hardening Assessment"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Reads /etc/ssh/sshd_config and host key metadata only - no network connections made"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating SSH daemon configuration..." "info"
    Write-Host ""

    $testId      = "LINUX-SSH-HARDENING"
    $sshdConfig  = "/etc/ssh/sshd_config"

    if (-not (Test-Path $sshdConfig)) {
        fncTestMessage "sshd_config not found at $sshdConfig - SSH may not be installed or path differs." "warning"
        return
    }

    # Parse config: strip comment lines and blanks, collect Include dirs too
    $rawLines = Get-Content $sshdConfig -ErrorAction SilentlyContinue
    $configLines = $rawLines | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }

    # Also pull in /etc/ssh/sshd_config.d/*.conf if present (OpenSSH 8.2+)
    $includePath = "/etc/ssh/sshd_config.d"
    if (Test-Path $includePath) {
        Get-ChildItem $includePath -Filter "*.conf" -ErrorAction SilentlyContinue | ForEach-Object {
            $extra = Get-Content $_.FullName -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
            if ($extra) { $configLines += $extra }
        }
    }

    function GetSshSetting ([string[]]$Lines, [string]$Setting) {
        $match = $Lines | Where-Object { $_ -match "^\s*$Setting\s+" } | Select-Object -Last 1
        if ($match -and $match -match "^\s*$Setting\s+(.+)") { return $matches[1].Trim() }
        return $null
    }

    # ----------------------------------------------------------------
    # PermitRootLogin
    # ----------------------------------------------------------------
    fncTestMessage "Checking PermitRootLogin..." "info"

    $permitRoot = GetSshSetting $configLines "PermitRootLogin"
    if (-not $permitRoot) { $permitRoot = "yes" }   # OpenSSH compile-time default

    if ($permitRoot -eq "yes") {

        $exploitation = @"
Direct root SSH access bypasses sudo audit trails and session accounting.
An attacker with root credentials (obtained via brute force, credential stuffing,
or from another compromised host) can authenticate directly without any
intermediate logging of the escalation path.

Tooling: hydra, medusa, ssh-audit
"@
        $remediation = @"
Edit /etc/ssh/sshd_config and set:

    PermitRootLogin no

Then restart the SSH daemon:

    sudo systemctl restart sshd

Verify:
    sshd -T | grep permitrootlogin
"@
        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "PERMIT_ROOT_LOGIN")) `
            -Title "SSH Root Login Permitted" `
            -Category "Remote Access Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message "PermitRootLogin is '$permitRoot'. Direct root authentication over SSH is allowed." `
            -Recommendation "Set PermitRootLogin no in /etc/ssh/sshd_config." `
            -Evidence @("PermitRootLogin = $permitRoot") `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation $remediation

    }
    else {
        fncTestMessage ("PermitRootLogin = '$permitRoot' [OK]") "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # PasswordAuthentication
    # ----------------------------------------------------------------
    fncTestMessage "Checking PasswordAuthentication..." "info"

    $passwordAuth = GetSshSetting $configLines "PasswordAuthentication"
    if (-not $passwordAuth) { $passwordAuth = "yes" }

    if ($passwordAuth -eq "yes") {

        $exploitation = @"
Password authentication exposes the service to brute-force and
credential-stuffing attacks. Compromised credentials from one system
can immediately be replayed against SSH.

Tooling: hydra, ncrack, ssh-audit
"@
        $remediation = @"
Ensure key-based authentication is configured for all users, then:

Edit /etc/ssh/sshd_config:

    PasswordAuthentication no
    AuthenticationMethods publickey

Restart sshd:

    sudo systemctl restart sshd
"@
        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "PASSWORD_AUTH")) `
            -Title "SSH Password Authentication Enabled" `
            -Category "Remote Access Security" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "PasswordAuthentication is '$passwordAuth'. Password-based SSH logins are accepted." `
            -Recommendation "Disable password authentication and enforce key-based auth." `
            -Evidence @("PasswordAuthentication = $passwordAuth") `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation $remediation

    }
    else {
        fncTestMessage ("PasswordAuthentication = '$passwordAuth' [OK]") "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # PermitEmptyPasswords
    # ----------------------------------------------------------------
    fncTestMessage "Checking PermitEmptyPasswords..." "info"

    $emptyPwd = GetSshSetting $configLines "PermitEmptyPasswords"

    if ($emptyPwd -eq "yes") {

        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "EMPTY_PASSWORDS")) `
            -Title "SSH Empty Passwords Permitted" `
            -Category "Remote Access Security" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message "PermitEmptyPasswords is 'yes'. Accounts with no password can authenticate over SSH without any credentials." `
            -Recommendation "Set PermitEmptyPasswords no in /etc/ssh/sshd_config and audit accounts for empty passwords." `
            -Evidence @("PermitEmptyPasswords = yes") `
            -SourceTests @($testId) `
            -Exploitation "Any account with an empty password provides unauthenticated root-equivalent SSH access if combined with PermitRootLogin." `
            -Remediation "Set PermitEmptyPasswords no in /etc/ssh/sshd_config. Identify empty-password accounts: sudo awk -F: '(`$2 == `"`") {print `$1}' /etc/shadow"

    }
    else {
        fncTestMessage "PermitEmptyPasswords = no [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # MaxAuthTries
    # ----------------------------------------------------------------
    fncTestMessage "Checking MaxAuthTries..." "info"

    $maxAuthTries = GetSshSetting $configLines "MaxAuthTries"
    $maxTriesVal  = if ($maxAuthTries) { [int]($maxAuthTries -replace '\D', '') } else { 6 }

    if ($maxTriesVal -gt 4) {

        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "MAX_AUTH_TRIES")) `
            -Title "SSH MaxAuthTries Above Recommended Threshold" `
            -Category "Remote Access Security" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "MaxAuthTries is $maxTriesVal. CIS recommends 4 or fewer to limit per-connection brute-force attempts." `
            -Recommendation "Set MaxAuthTries 3 in /etc/ssh/sshd_config." `
            -Evidence @("MaxAuthTries = $maxTriesVal") `
            -SourceTests @($testId)

    }
    else {
        fncTestMessage ("MaxAuthTries = $maxTriesVal [OK]") "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # X11Forwarding
    # ----------------------------------------------------------------
    fncTestMessage "Checking X11Forwarding..." "info"

    $x11 = GetSshSetting $configLines "X11Forwarding"

    if ($x11 -eq "yes") {

        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "X11_FORWARDING")) `
            -Title "SSH X11 Forwarding Enabled" `
            -Category "Remote Access Security" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "X11Forwarding is 'yes'. Graphical session forwarding increases attack surface and can be abused for session hijacking." `
            -Recommendation "Set X11Forwarding no in /etc/ssh/sshd_config unless explicitly required." `
            -Evidence @("X11Forwarding = yes") `
            -SourceTests @($testId)

    }
    else {
        fncTestMessage "X11Forwarding = no [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # AllowTcpForwarding
    # ----------------------------------------------------------------
    fncTestMessage "Checking AllowTcpForwarding..." "info"

    $tcpFwd = GetSshSetting $configLines "AllowTcpForwarding"

    if (-not $tcpFwd -or $tcpFwd -eq "yes") {

        $effective = if ($tcpFwd) { $tcpFwd } else { "yes (OpenSSH default)" }

        $exploitation = @"
SSH TCP forwarding allows authenticated users to tunnel arbitrary TCP
traffic through the SSH connection, effectively turning the server
into a SOCKS proxy. This is routinely used for C2 redirection and
lateral movement into otherwise unreachable internal segments.

Tooling: ssh -D (SOCKS), ssh -L (local forward), ssh -R (reverse tunnel)
"@
        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "TCP_FORWARDING")) `
            -Title "SSH TCP Forwarding Enabled" `
            -Category "Remote Access Security" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "AllowTcpForwarding is '$effective'. SSH can be used as a tunnel for lateral movement or C2 redirection." `
            -Recommendation "Set AllowTcpForwarding no in /etc/ssh/sshd_config unless port forwarding is operationally required." `
            -Evidence @("AllowTcpForwarding = $effective") `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation "Set AllowTcpForwarding no in /etc/ssh/sshd_config and restart sshd."

    }
    else {
        fncTestMessage ("AllowTcpForwarding = '$tcpFwd' [OK]") "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # LoginGraceTime
    # ----------------------------------------------------------------
    fncTestMessage "Checking LoginGraceTime..." "info"

    $graceTime = GetSshSetting $configLines "LoginGraceTime"
    $graceSecs = 120  # OpenSSH default

    if ($graceTime) {
        if ($graceTime -match '^(\d+)m$')  { $graceSecs = [int]$matches[1] * 60 }
        elseif ($graceTime -match '^(\d+)$') { $graceSecs = [int]$matches[1] }
    }

    if ($graceSecs -gt 60) {

        fncSubmitFinding `
            -Id ("LSSH-" + (fncShortHashTag "LOGIN_GRACE_TIME")) `
            -Title "SSH LoginGraceTime Exceeds Recommended Threshold" `
            -Category "Remote Access Security" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "LoginGraceTime is ${graceSecs}s. A long grace period extends the window for unauthenticated connection flooding." `
            -Recommendation "Set LoginGraceTime 30 in /etc/ssh/sshd_config." `
            -Evidence @("LoginGraceTime = ${graceSecs}s") `
            -SourceTests @($testId)

    }
    else {
        fncTestMessage ("LoginGraceTime = ${graceSecs}s [OK]") "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Host private key permissions
    # ----------------------------------------------------------------
    fncTestMessage "Checking SSH host private key permissions..." "info"

    try {

        $hostKeys = Get-ChildItem "/etc/ssh/" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^ssh_host_.+_key$' -and -not $_.PSIsContainer }

        foreach ($key in $hostKeys) {

            $perms = (& bash -c ("stat -c '%a' '{0}' 2>/dev/null" -f $key.FullName)).Trim()

            if ($perms -and [int]$perms -gt 600) {

                fncSubmitFinding `
                    -Id ("LSSH-" + (fncShortHashTag ("HOSTKEY_PERMS_" + $key.Name))) `
                    -Title "SSH Host Private Key Has Excessive Permissions" `
                    -Category "Remote Access Security" `
                    -Severity "Medium" `
                    -Status "Detected" `
                    -Message ("Host private key '{0}' has permissions {1} (expected 600 or stricter)." -f $key.Name, $perms) `
                    -Recommendation "Restrict SSH host private key permissions: sudo chmod 600 /etc/ssh/ssh_host_*_key" `
                    -Evidence @(("{0} : permissions {1}" -f $key.FullName, $perms)) `
                    -SourceTests @($testId) `
                    -Exploitation "A readable host private key allows an attacker to impersonate the server for man-in-the-middle attacks against connecting clients." `
                    -Remediation "Run: sudo chmod 600 /etc/ssh/ssh_host_*_key"

            }
            else {
                fncTestMessage ("{0} permissions = {1} [OK]" -f $key.Name, $perms) "proten"
            }
        }

    }
    catch {}

    Write-Host ""
    fncTestMessage "SSH hardening assessment complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxSshHardening", "fncGetMappings_LINUX_SSH_HARDENING")
