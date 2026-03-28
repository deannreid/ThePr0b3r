# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/" }
        [pscustomobject]@{ Id = "T1070"; Name = "Indicator Removal on Host"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1070/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-778"; Name = "Insufficient Logging"; Url = "https://cwe.mitre.org/data/definitions/778.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-11"; Name = "Audit Record Retention"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SI-4"; Name = "System Monitoring"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_WEF_CONFIG_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckWEFConfiguration
# Purpose : Identify gaps in Windows Event Forwarding configuration
# Notes   : Red-team visibility assessment of whether host logs are
#           forwarded off-box before an operator can tamper with them
# ================================================================
function fncCheckWEFConfiguration {

    fncPrintSectionHeader "Windows Event Forwarding Exposure"

    $Risk = "Low"
    $RiskReason = "Performs read-only inspection of Windows Event Forwarding configuration, services, and registry policy settings"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Assessing off-host log forwarding visibility..." "info"

# ------------------------------------------------------------
# Base Text
# ------------------------------------------------------------

$baseExploitation = @"
Windows Event Forwarding reduces the value of on-host log tampering by
moving telemetry away from the endpoint.

From a red team perspective, weak or absent WEF coverage creates a safer
operating environment for:

- Clearing or truncating local logs
- Disabling event channels before actions
- Blending into short-lived local telemetry
- Reducing defender ability to reconstruct activity
- Limiting post-compromise timeline accuracy

If a host is not forwarding security-relevant telemetry, attackers gain
more freedom to impair defenses locally without immediate off-host evidence.
"@

$baseRemediation = @"
Configure Windows Event Forwarding centrally and ensure critical telemetry
is forwarded off-host.

Recommended actions:

1) Ensure the Windows Event Collector service is correctly configured where relevant.
2) Ensure the Windows Remote Management service is operational.
3) Configure source-initiated or collector-initiated subscriptions as required.
4) Forward high-value telemetry including:
   - Security log
   - PowerShell Operational
   - WMI Activity
   - Sysmon (if deployed)
   - Defender operational events
5) Validate collector reachability and subscription health.
6) Monitor for changes to forwarding configuration.
"@

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

    fncTestMessage "Administrator privileges required to validate WEF configuration." "specpriv"

    $exploitationText = "Without elevated access, off-host log forwarding coverage cannot be validated."
    $remediationText = "Run this validation as an administrator."

    fncSubmitFinding `
        -Id ("WEF-" + (fncShortHashTag "ADMIN_REQUIRED")) `
        -Category "Defense Evasion" `
        -Title "WEF Validation Requires Administrative Privileges" `
        -Severity "Low" `
        -Status "Mixed / Unclear" `
        -Message "Administrator privileges required to enumerate Windows Event Forwarding configuration." `
        -Recommendation "Run the check with administrative privileges." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    return
}

# ------------------------------------------------------------
# WinRM Service State
# ------------------------------------------------------------

$winrmRunning = $false
$winrmStartup = "Unknown"

try {

    $winrmSvc = Get-Service -Name "WinRM" -ErrorAction Stop
    $winrmInfo = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop

    if ($winrmSvc.Status -eq "Running") {
        $winrmRunning = $true
    }

    $winrmStartup = $winrmInfo.StartMode

    fncTestMessage ("WinRM startup type detected: {0}" -f $winrmStartup) "active"

} catch {

    fncTestMessage "Unable to inspect WinRM service state." "warning"
}

if ($winrmRunning) {

    fncTestMessage "WinRM service active." "active"

} else {

    fncTestMessage "WinRM service not running." "specpriv"

    fncSubmitFinding `
        -Id ("WEF-" + (fncShortHashTag "WINRM_STOPPED")) `
        -Category "Defense Evasion" `
        -Title "WinRM Not Available For Event Forwarding" `
        -Severity "Medium" `
        -Status "Likely Exposed" `
        -Message "WinRM is not running, which may prevent Windows Event Forwarding from operating correctly." `
        -Recommendation "Ensure WinRM is enabled and operational where WEF is expected." `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation
}

if ($winrmStartup -eq "Auto") {

    fncTestMessage "WinRM configured for automatic startup." "proten"

} elseif ($winrmStartup -ne "Unknown") {

    fncTestMessage ("WinRM startup type is {0}." -f $winrmStartup) "warning"
}

# ------------------------------------------------------------
# Collector Service State
# ------------------------------------------------------------

$wecsvcPresent = $false
$wecsvcRunning = $false

try {

    $wecSvc = Get-Service -Name "Wecsvc" -ErrorAction Stop
    $wecInfo = Get-CimInstance Win32_Service -Filter "Name='Wecsvc'" -ErrorAction Stop

    $wecsvcPresent = $true

    if ($wecSvc.Status -eq "Running") {
        $wecsvcRunning = $true
    }

    fncTestMessage ("Wecsvc startup type detected: {0}" -f $wecInfo.StartMode) "active"

} catch {

    fncTestMessage "Windows Event Collector service not available or not queryable." "warning"
}

if ($wecsvcPresent) {

    if ($wecsvcRunning) {
        fncTestMessage "Windows Event Collector service active." "active"
    } else {
        fncTestMessage "Windows Event Collector service present but not running." "warning"
    }
}

# ------------------------------------------------------------
# WEF Registry Configuration
# ------------------------------------------------------------

$subscriptionManagerConfigured = $false
$subscriptionManagerValues = @()
$wefRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"

try {

    if (Test-Path $wefRegPath) {

        $regProps = Get-ItemProperty -Path $wefRegPath -ErrorAction SilentlyContinue

        foreach ($prop in $regProps.PSObject.Properties) {

            if ($prop.Name -match '^\d+$' -and -not [string]::IsNullOrWhiteSpace($prop.Value)) {

                $subscriptionManagerConfigured = $true
                $subscriptionManagerValues += [string]$prop.Value
            }
        }
    }

} catch {

    fncTestMessage "Unable to inspect WEF SubscriptionManager registry configuration." "warning"
}

if ($subscriptionManagerConfigured) {

    fncTestMessage "SubscriptionManager configuration present." "proten"

    foreach ($entry in ($subscriptionManagerValues | Select-Object -First 5)) {
        fncTestMessage ("Subscription manager entry: {0}" -f $entry) "link"
    }

} else {

    fncTestMessage "No SubscriptionManager configuration detected." "specpriv"
}

# ------------------------------------------------------------
# Runtime Subscription Visibility
# ------------------------------------------------------------

$subscriptionNames = @()

try {

    $subOutput = wecutil es 2>$null

    foreach ($line in $subOutput) {

        $trimmed = "$line".Trim()

        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            $subscriptionNames += $trimmed
        }
    }

} catch {

    fncTestMessage "Unable to enumerate WEF subscriptions with wecutil." "warning"
}

if ($subscriptionNames.Count -gt 0) {

    fncTestMessage ("WEF subscriptions detected: {0}" -f $subscriptionNames.Count) "active"

    foreach ($sub in ($subscriptionNames | Select-Object -First 5)) {
        fncTestMessage ("Subscription discovered: {0}" -f $sub) "link"
    }

} else {

    fncTestMessage "No active WEF subscriptions discovered." "warning"
}

# ------------------------------------------------------------
# Identify Exposure
# ------------------------------------------------------------

$wefWeak = $false
$issues = @()

if (-not $winrmRunning) {
    $wefWeak = $true
    $issues += "WinRM not running"
}

if (-not $subscriptionManagerConfigured -and $subscriptionNames.Count -eq 0) {
    $wefWeak = $true
    $issues += "No WEF subscription configuration detected"
}

if ($subscriptionManagerConfigured -and $subscriptionNames.Count -eq 0) {
    $issues += "Registry configuration present but no active subscriptions enumerated"
}

# ------------------------------------------------------------
# Findings
# ------------------------------------------------------------

if ($wefWeak) {

    $issueText = ($issues | Select-Object -Unique) -join ", "

    fncSubmitFinding `
        -Id ("WEF-" + (fncShortHashTag "WEF_WEAK_OR_ABSENT")) `
        -Category "Defense Evasion" `
        -Title "Windows Event Forwarding Weak Or Absent" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message ("Off-host log forwarding appears weak or absent. Observed issues: {0}" -f $issueText) `
        -Recommendation "Configure reliable Windows Event Forwarding and ensure collector connectivity." `
        -Exploitation $baseExploitation `
        -Remediation $baseRemediation

    return
}

if ($issues.Count -gt 0) {

    $issueText = ($issues | Select-Object -Unique) -join ", "

    fncTestMessage ("WEF partially present but issues remain: {0}" -f $issueText) "warning"

    $exploitationText = "Attackers may still benefit if forwarding exists only on paper or is not functioning reliably."

    fncSubmitFinding `
        -Id ("WEF-" + (fncShortHashTag "WEF_PARTIAL")) `
        -Category "Defense Evasion" `
        -Title "Windows Event Forwarding Partially Configured" `
        -Severity "Medium" `
        -Status "Mixed / Unclear" `
        -Message ("Windows Event Forwarding appears present but has gaps: {0}" -f $issueText) `
        -Recommendation "Review collector health and active subscription state." `
        -Exploitation $exploitationText `
        -Remediation $baseRemediation

    return
}

fncTestMessage "Windows Event Forwarding configuration appears present." "proten"

fncSubmitFinding `
    -Id ("WEF-" + (fncShortHashTag "WEF_PRESENT")) `
    -Category "Defense Evasion" `
    -Title "Windows Event Forwarding Present" `
    -Severity "Info" `
    -Status "Protected" `
    -Message "Windows Event Forwarding configuration appears present and dependencies are available." `
    -Recommendation "Maintain current forwarding coverage and validate high-value subscriptions regularly." `
    -Exploitation $baseExploitation `
    -Remediation "No remediation required."

fncTestMessage "https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection" "link"
fncTestMessage "https://attack.mitre.org/techniques/T1070/" "link"

}

Export-ModuleMember -Function @("fncCheckWEFConfiguration", "fncGetMappings_WEF_CONFIG_CHECK")