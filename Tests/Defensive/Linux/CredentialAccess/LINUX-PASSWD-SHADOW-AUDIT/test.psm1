# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1003.008"; Name = "OS Credential Dumping: /etc/passwd and /etc/shadow"; Tactic = "Credential Access"; Url = "https://attack.mitre.org/techniques/T1003/008/" }
        [pscustomobject]@{ Id = "T1078.003"; Name = "Valid Accounts: Local Accounts";                    Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1078/003/" }
        [pscustomobject]@{ Id = "T1136.001"; Name = "Create Account: Local Account";                     Tactic = "Persistence";     Url = "https://attack.mitre.org/techniques/T1136/001/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-521"; Name = "Weak Password Requirements";                          Url = "https://cwe.mitre.org/data/definitions/521.html" }
        [pscustomobject]@{ Id = "CWE-916"; Name = "Use of Password Hash With Insufficient Computational Effort"; Url = "https://cwe.mitre.org/data/definitions/916.html" }
        [pscustomobject]@{ Id = "CWE-732"; Name = "Incorrect Permission Assignment for Critical Resource"; Url = "https://cwe.mitre.org/data/definitions/732.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "IA-5";  Name = "Authenticator Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AC-2";  Name = "Account Management";       Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SC-28"; Name = "Protection of Information at Rest"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "6.2.1"; Name = "Ensure accounts in /etc/passwd use shadowed passwords";  Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Verify all accounts use x in the password field to enforce shadow password use." }
        [pscustomobject]@{ Id = "6.2.2"; Name = "Ensure /etc/shadow password fields are not empty";       Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "All accounts must have a password or be locked to prevent unauthenticated access." }
        [pscustomobject]@{ Id = "6.2.3"; Name = "Ensure all groups in /etc/passwd exist in /etc/group";   Url = "https://www.cisecurity.org/benchmark/ubuntu_linux"; Version = "2.0.0"; BenchmarkId = "CIS Ubuntu Linux 22.04 LTS"; Description = "Avoid orphaned group references in /etc/passwd." }
    )
}

function fncGetMappings_LINUX_PASSWD_SHADOW_AUDIT { return $script:Mappings }

# ================================================================
# Function: fncCheckLinuxPasswdShadow
# Purpose : Audit /etc/passwd and /etc/shadow for security issues
# ================================================================
function fncCheckLinuxPasswdShadow {

    fncSafeSectionHeader "Password and Shadow File Security Audit"

    if (-not $IsLinux) {
        fncTestMessage "This test requires a Linux host. Skipping." "warning"
        return
    }

    $Risk       = "Safe"
    $RiskReason = "Read-only inspection of /etc/passwd and /etc/shadow metadata - no credentials extracted or modified"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Auditing /etc/passwd and /etc/shadow security configuration..." "info"
    Write-Host ""

    $testId = "LINUX-PASSWD-SHADOW-AUDIT"

    # ----------------------------------------------------------------
    # Parse /etc/passwd
    # ----------------------------------------------------------------
    if (-not (Test-Path "/etc/passwd")) {
        fncTestMessage "/etc/passwd not found. Skipping." "warning"
        return
    }

    $passwdLines = Get-Content "/etc/passwd" -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch '^\s*#' -and $_ -match ':' }

    # ----------------------------------------------------------------
    # UID 0 accounts other than root
    # ----------------------------------------------------------------
    fncTestMessage "Checking for duplicate UID 0 (root-equivalent) accounts..." "info"

    $uid0Accounts = $passwdLines | Where-Object {
        $parts = $_ -split ':'
        $parts.Count -ge 4 -and $parts[2] -eq '0' -and $parts[0] -ne 'root'
    } | ForEach-Object { ($_ -split ':')[0] }

    if ($uid0Accounts) {
        $exploitation = @"
Accounts with UID 0 have root-equivalent privileges on the system.
An attacker who gains access to any UID 0 account has full system control
without needing to escalate privileges.

Tooling: su <account>, ssh -l <account> <host>
"@
        $remediation = @"
Investigate each UID 0 account and remove or reassign:

    sudo usermod -u <new_uid> <username>

or delete the account entirely:

    sudo userdel <username>

Audit creation source: last <username>, ausearch -ua <uid>
"@
        fncSubmitFinding `
            -Id ("LPSW-" + (fncShortHashTag "DUPLICATE_UID0")) `
            -Title "Duplicate UID 0 (Root-Equivalent) Accounts Detected" `
            -Category "Account Security" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("$(@($uid0Accounts).Count) non-root account(s) have UID 0, granting root-equivalent privileges.") `
            -Recommendation "Investigate and remove all UID 0 accounts that are not the canonical root account." `
            -Evidence @($uid0Accounts | ForEach-Object { "UID 0: $_" }) `
            -SourceTests @($testId) `
            -Exploitation $exploitation `
            -Remediation $remediation
    }
    else {
        fncTestMessage "No duplicate UID 0 accounts found [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Accounts with passwords stored directly in /etc/passwd (not shadowed)
    # ----------------------------------------------------------------
    fncTestMessage "Checking for non-shadowed password entries in /etc/passwd..." "info"

    $nonShadowed = $passwdLines | Where-Object {
        $parts = $_ -split ':'
        $parts.Count -ge 2 -and $parts[1] -ne 'x' -and $parts[1] -ne '*' -and $parts[1] -ne '!' -and $parts[1] -ne ''
    } | ForEach-Object {
        $p = $_ -split ':'
        "$($p[0]) (password field: '$($p[1])')"
    }

    if ($nonShadowed) {
        fncSubmitFinding `
            -Id ("LPSW-" + (fncShortHashTag "PASSWD_NOT_SHADOWED")) `
            -Title "Password Hashes Stored Directly in /etc/passwd" `
            -Category "Credential Access" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("$(@($nonShadowed).Count) account(s) have password hashes in /etc/passwd rather than /etc/shadow. /etc/passwd is world-readable.") `
            -Recommendation "Convert all accounts to shadow passwords: sudo pwconv" `
            -Evidence @($nonShadowed) `
            -SourceTests @($testId) `
            -Exploitation "World-readable hashes in /etc/passwd can be cracked offline: hashcat, john --format=crypt /etc/passwd" `
            -Remediation "Run: sudo pwconv`nThis migrates all password hashes to /etc/shadow and replaces them with 'x' in /etc/passwd."
    }
    else {
        fncTestMessage "All accounts use shadow passwords [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # /etc/shadow permissions
    # ----------------------------------------------------------------
    fncTestMessage "Checking /etc/shadow file permissions..." "info"

    if (Test-Path "/etc/shadow") {

        $shadowPerms = (& bash -c "stat -c '%a %U %G' /etc/shadow 2>/dev/null").Trim()

        if ($shadowPerms) {
            $parts     = $shadowPerms -split ' '
            $octal     = $parts[0]
            $owner     = if ($parts.Count -gt 1) { $parts[1] } else { "unknown" }
            $group     = if ($parts.Count -gt 2) { $parts[2] } else { "unknown" }
            $octalInt  = [int]$octal

            # World-readable or group-readable by non-shadow group
            $worldReadable = ($octalInt -band 4) -gt 0
            $groupReadable = ($octalInt -band 040) -gt 0
            $notRootOwned  = $owner -ne "root"

            if ($worldReadable -or $notRootOwned) {
                fncSubmitFinding `
                    -Id ("LPSW-" + (fncShortHashTag "SHADOW_PERMS")) `
                    -Title "/etc/shadow Has Excessive Permissions" `
                    -Category "Credential Access" `
                    -Severity "Critical" `
                    -Status "Detected" `
                    -Message ("/etc/shadow permissions: $octal (owner: $owner, group: $group). Shadow file should be 640 root:shadow or stricter.") `
                    -Recommendation "Restrict /etc/shadow: sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow" `
                    -Evidence @("/etc/shadow: $shadowPerms") `
                    -SourceTests @($testId) `
                    -Exploitation "A readable /etc/shadow exposes all password hashes for offline cracking with hashcat or john." `
                    -Remediation "sudo chmod 640 /etc/shadow`nsudo chown root:shadow /etc/shadow"
            }
            else {
                fncTestMessage ("/etc/shadow permissions = $octal (owner: $owner, group: $group) [OK]") "proten"
            }
        }

    }
    else {
        fncTestMessage "/etc/shadow not found - shadow passwords may not be in use." "warning"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Empty passwords in /etc/shadow
    # ----------------------------------------------------------------
    fncTestMessage "Checking for empty passwords in /etc/shadow..." "info"

    $emptyPasswdAccounts = [System.Collections.Generic.List[string]]::new()

    try {
        $shadowReadable = (& bash -c "test -r /etc/shadow 2>/dev/null && echo y").Trim() -eq "y"

        if ($shadowReadable) {
            Get-Content "/etc/shadow" -ErrorAction SilentlyContinue |
                Where-Object { $_ -match ':([^:]*):' } |
                ForEach-Object {
                    $parts = $_ -split ':'
                    if ($parts.Count -ge 2 -and $parts[1] -eq '') {
                        $emptyPasswdAccounts.Add($parts[0])
                    }
                }
        }
        else {
            fncTestMessage "Cannot read /etc/shadow (requires root). Skipping empty password check." "warning"
        }
    }
    catch {}

    if ($emptyPasswdAccounts.Count -gt 0) {
        fncSubmitFinding `
            -Id ("LPSW-" + (fncShortHashTag "EMPTY_SHADOW_PASSWD")) `
            -Title "Accounts With Empty Passwords Detected" `
            -Category "Credential Access" `
            -Severity "Critical" `
            -Status "Detected" `
            -Message ("$($emptyPasswdAccounts.Count) account(s) have empty password fields in /etc/shadow. These can authenticate without a password.") `
            -Recommendation "Lock or assign passwords to all accounts immediately." `
            -Evidence @($emptyPasswdAccounts | ForEach-Object { "Empty password: $_" }) `
            -SourceTests @($testId) `
            -Exploitation "Accounts with empty passwords can be accessed immediately: su <user> (no password required)." `
            -Remediation "Lock account: sudo passwd -l <username>`nOr set a strong password: sudo passwd <username>`nAudit how the empty password was set: ausearch -ua <uid>"
    }
    elseif ($emptyPasswdAccounts.Count -eq 0 -and ((& bash -c "test -r /etc/shadow 2>/dev/null && echo y").Trim() -eq "y")) {
        fncTestMessage "No accounts with empty passwords found [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Weak password hash algorithms in /etc/shadow
    # ----------------------------------------------------------------
    fncTestMessage "Checking password hash algorithms in /etc/shadow..." "info"

    $weakHashAccounts = [System.Collections.Generic.List[string]]::new()

    try {
        $shadowReadable = (& bash -c "test -r /etc/shadow 2>/dev/null && echo y").Trim() -eq "y"

        if ($shadowReadable) {
            Get-Content "/etc/shadow" -ErrorAction SilentlyContinue |
                Where-Object { $_ -match ':(\$[^:]+):' } |
                ForEach-Object {
                    $parts = $_ -split ':'
                    if ($parts.Count -ge 2) {
                        $hash = $parts[1]
                        $algo = $null
                        if     ($hash -match '^\$1\$')  { $algo = "MD5 (\$1\$)" }
                        elseif ($hash -match '^\$2[aby]\$') { $algo = "bcrypt (\$2a/2b\$)" }
                        elseif ($hash -match '^\$5\$')  { $algo = "SHA-256 (\$5\$)" }
                        elseif ($hash -match '^\$6\$')  { $algo = $null }  # SHA-512 - OK
                        elseif ($hash -match '^\$y\$')  { $algo = $null }  # yescrypt - OK
                        elseif ($hash -match '^\$gy\$') { $algo = $null }  # gost-yescrypt - OK
                        elseif ($hash -match '^\$7\$')  { $algo = $null }  # scrypt - OK
                        elseif ($hash -notmatch '^\$')  { $algo = "DES (legacy)" }

                        if ($algo) {
                            $weakHashAccounts.Add("$($parts[0]): $algo")
                        }
                    }
                }
        }
    }
    catch {}

    if ($weakHashAccounts.Count -gt 0) {
        fncSubmitFinding `
            -Id ("LPSW-" + (fncShortHashTag "WEAK_HASH_ALGO")) `
            -Title "Accounts Using Weak Password Hash Algorithms" `
            -Category "Credential Access" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$($weakHashAccounts.Count) account(s) use outdated password hash algorithms (MD5, DES, or SHA-256). These are significantly faster to crack than SHA-512 or yescrypt.") `
            -Recommendation "Reconfigure PAM to use yescrypt or SHA-512 and force password resets." `
            -Evidence @($weakHashAccounts) `
            -SourceTests @($testId) `
            -Exploitation "MD5/DES hashes crack orders of magnitude faster: hashcat -m 500 (MD5-crypt), hashcat -m 1500 (DES-crypt).`nA GPU cluster can test billions of MD5-crypt hashes per second." `
            -Remediation "Update /etc/login.defs: set ENCRYPT_METHOD yescrypt`nUpdate /etc/pam.d/common-password: add rounds=4096`nForce password resets: sudo chage -d 0 <username>`nUsers must re-login and set new passwords to get rehashed."
    }
    elseif ($weakHashAccounts.Count -eq 0 -and ((& bash -c "test -r /etc/shadow 2>/dev/null && echo y").Trim() -eq "y")) {
        fncTestMessage "All password hashes use strong algorithms [OK]" "proten"
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # Accounts with no-login shell that still have valid password hashes
    # ----------------------------------------------------------------
    fncTestMessage "Checking service accounts with interactive shells..." "info"

    $serviceWithShell = $passwdLines | Where-Object {
        $parts = $_ -split ':'
        if ($parts.Count -lt 7) { return $false }
        $uid   = [int]($parts[2] -replace '\D', '0')
        $shell = $parts[6].Trim()
        # UID < 1000 = system account, but has an interactive shell
        $uid -gt 0 -and $uid -lt 1000 -and
        $shell -notmatch 'nologin|false|sync|shutdown|halt' -and
        $shell -match '/(bash|sh|zsh|fish|ksh|csh|tcsh|dash)$'
    } | ForEach-Object {
        $p = $_ -split ':'
        "$($p[0]) (UID $($p[2]), shell: $($p[6].Trim()))"
    }

    if ($serviceWithShell) {
        fncSubmitFinding `
            -Id ("LPSW-" + (fncShortHashTag "SERVICE_SHELL")) `
            -Title "System Accounts Have Interactive Login Shells" `
            -Category "Account Security" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("$(@($serviceWithShell).Count) system account(s) (UID < 1000) have interactive shells. If compromised, these provide a persistent shell session.") `
            -Recommendation "Set non-interactive shells for service accounts: sudo usermod -s /usr/sbin/nologin <account>" `
            -Evidence @($serviceWithShell) `
            -SourceTests @($testId) `
            -Exploitation "Service accounts with shells can be used as persistence mechanisms via SSH keys or cron jobs without appearing as obvious user accounts." `
            -Remediation "For each service account: sudo usermod -s /usr/sbin/nologin <account>`nVerify no legitimate service requires an interactive shell."
    }
    else {
        fncTestMessage "No unexpected service account shells found [OK]" "proten"
    }

    Write-Host ""
    fncTestMessage "Password and shadow file audit complete." "info"
}

Export-ModuleMember -Function @("fncCheckLinuxPasswdShadow", "fncGetMappings_LINUX_PASSWD_SHADOW_AUDIT")
