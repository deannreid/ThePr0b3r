# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SI-4"; Name = "System Monitoring"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "SI-3"; Name = "Malicious Code Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_SECURITY_CENTER_SERVICE_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckSecurityCenterServiceState
# Purpose : Identify security service weaknesses from a red team
#           perspective that could enable defense evasion.
# Notes   : Detects service tampering, disabled logging,
#           AV shutdown opportunities, and persistence paths.
# ================================================================
function fncCheckSecurityCenterServiceState {

    fncPrintSectionHeader "Security Control Service Exposure"

    $Risk = "Low"
    $RiskReason = "Performs read-only service, CIM, registry, and recovery configuration queries to identify defensive service weaknesses"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Assessing defensive services attackers commonly target..." "info"

    # ------------------------------------------------------------
    # Services attackers frequently disable
    # ------------------------------------------------------------

    $services = @(
        @{ Name = "wscsvc"; Friendly = "Security Center"; Severity = "Medium" }
        @{ Name = "WinDefend"; Friendly = "Windows Defender"; Severity = "High" }
        @{ Name = "wuauserv"; Friendly = "Windows Update"; Severity = "Medium" }
        @{ Name = "EventLog"; Friendly = "Windows Event Log"; Severity = "High" }
        @{ Name = "WinRM"; Friendly = "WinRM"; Severity = "Low" }
        @{ Name = "RemoteRegistry"; Friendly = "Remote Registry"; Severity = "Low" }

        # Endpoint Protection
        @{ Name = "Sense"; Friendly = "Microsoft Defender for Endpoint"; Severity = "High" }
        @{ Name = "WdNisSvc"; Friendly = "Defender Network Inspection Service"; Severity = "High" }
        @{ Name = "WdFilter"; Friendly = "Defender File System Filter"; Severity = "High" }

        # Logging / Telemetry
        @{ Name = "eventlog"; Friendly = "Windows Event Log"; Severity = "High" }
        @{ Name = "SysMain"; Friendly = "SysMain Telemetry"; Severity = "Low" }
        @{ Name = "DiagTrack"; Friendly = "Connected User Experiences and Telemetry"; Severity = "Low" }

        # Credential / Authentication
        @{ Name = "KeyIso"; Friendly = "Cryptographic Key Isolation"; Severity = "Medium" }
        @{ Name = "SamSs"; Friendly = "Security Accounts Manager"; Severity = "High" }
        @{ Name = "Netlogon"; Friendly = "Netlogon"; Severity = "High" }
        @{ Name = "Kdc"; Friendly = "Kerberos Key Distribution Center"; Severity = "High" }

        # Remote Management / Lateral Movement
        @{ Name = "TermService"; Friendly = "Remote Desktop Services"; Severity = "Medium" }
        @{ Name = "LanmanServer"; Friendly = "SMB Server"; Severity = "Medium" }
        @{ Name = "LanmanWorkstation"; Friendly = "SMB Client"; Severity = "Medium" }

        # Update / Patch Enforcement
        @{ Name = "UsoSvc"; Friendly = "Update Orchestrator Service"; Severity = "Medium" }
        @{ Name = "TrustedInstaller"; Friendly = "Windows Modules Installer"; Severity = "Medium" }

        # Firewall / Network Protection
        @{ Name = "MpsSvc"; Friendly = "Windows Firewall"; Severity = "High" }
        @{ Name = "BFE"; Friendly = "Base Filtering Engine"; Severity = "High" }

        # SmartScreen / Application Protection
        @{ Name = "AppIDSvc"; Friendly = "Application Identity"; Severity = "Medium" }
        @{ Name = "Appinfo"; Friendly = "Application Information"; Severity = "Medium" }

        # Time / Domain Integrity
        @{ Name = "W32Time"; Friendly = "Windows Time Service"; Severity = "Low" }

        # Task Execution / Persistence
        @{ Name = "Schedule"; Friendly = "Task Scheduler"; Severity = "High" }
    )

    # ------------------------------------------------------------
    # References
    # ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/001/" "link"
    fncTestMessage "https://attack.mitre.org/techniques/T1543/003/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/windows/win32/services/services" "link"

    foreach ($svc in $services) {

        $name = $svc.Name
        $friendly = $svc.Friendly
        $severity = $svc.Severity

        fncTestMessage ("Inspecting service: {0}" -f $friendly) "info"

        # ------------------------------------------------------------
        # Service Discovery
        # ------------------------------------------------------------

        try {

            $service = Get-Service -Name $name -ErrorAction Stop
            $svcInfo = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name)

            fncTestMessage ("Service discovered: {0}" -f $friendly) "active"

        }
        catch {

            $exploitationText = @"
The $friendly service could not be located on the system.

Attackers may tamper with or remove defensive services to reduce
visibility, disable protections, or establish persistence.

Missing core security services can indicate:

- Service tampering
- Operating system corruption
- Malicious removal or modification
- Unexpected hardening drift
"@

            $remediationText = @"
Investigate the integrity of this system immediately.

Recommended actions:

1) Verify the expected service exists for this platform.
2) Review recent administrative and security changes.
3) Restore the missing service if appropriate.
4) Validate system integrity using trusted repair methods.
5) Confirm security controls are operating as intended.
"@

            fncTestMessage ("Service missing: {0}" -f $friendly) "specpriv"

            fncSubmitFinding `
                -Id ("SERVICE-" + (fncShortHashTag ($name + "_MISSING"))) `
                -Category "Defense Evasion" `
                -Title ("{0} Service Missing" -f $friendly) `
                -Severity "High" `
                -Status "Detected" `
                -Message ("The {0} service is missing from the system." -f $friendly) `
                -Recommendation "Investigate system tampering." `
                -Exploitation $exploitationText `
                -Remediation $remediationText

            continue
        }

        # ------------------------------------------------------------
        # Service Running State
        # ------------------------------------------------------------

        if ($service.Status -ne "Running") {

            $exploitationText = @"
The $friendly service is not running.

Attackers frequently stop security-relevant services to reduce
visibility or bypass protections before performing further activity.

Stopping this service may allow:

- Reduced defensive visibility
- Weakened endpoint protections
- Lower likelihood of security alerts
- Easier persistence or lateral movement
"@

            $remediationText = @"
Ensure the $friendly service is operational.

Recommended actions:

1) Start the service.
2) Determine why the service stopped.
3) Review related security alerts and system logs.
4) Confirm startup configuration is correct.
5) Monitor for repeated service stoppage or tampering.
"@

            fncTestMessage ("{0} service not running." -f $friendly) "specpriv"

            fncSubmitFinding `
                -Id ("SERVICE-" + (fncShortHashTag ($name + "_STOPPED"))) `
                -Category "Defense Evasion" `
                -Title ("{0} Service Stopped" -f $friendly) `
                -Severity $severity `
                -Status "Detected" `
                -Message ("The {0} service is currently stopped." -f $friendly) `
                -Recommendation ("Ensure the {0} service remains operational." -f $friendly) `
                -Exploitation $exploitationText `
                -Remediation $remediationText

        }
        else {

            fncTestMessage ("{0} service active." -f $friendly) "proten"
        }

        # ------------------------------------------------------------
        # Startup Configuration
        # ------------------------------------------------------------

        $startup = $svcInfo.StartMode

        if ($startup -ne "Auto") {

            $exploitationText = @"
The $friendly service is not configured for automatic startup.

A delayed, manual, or disabled startup configuration may allow
security telemetry or protections to remain unavailable after reboot.

Attackers sometimes modify service startup mode to suppress defenses
without needing to stop the service immediately.
"@

            $remediationText = @"
Set the $friendly service startup type to Automatic where appropriate.

Recommended actions:

1) Review the intended baseline for this service.
2) Set the service to Automatic if required.
3) Validate the service starts correctly after reboot.
4) Monitor for unauthorized startup changes.
"@

            fncTestMessage ("{0} startup type: {1}" -f $friendly, $startup) "specpriv"

            fncSubmitFinding `
                -Id ("SERVICE-" + (fncShortHashTag ($name + "_STARTUP"))) `
                -Category "Defense Evasion" `
                -Title ("{0} Startup Misconfigured" -f $friendly) `
                -Severity "Medium" `
                -Status "Detected" `
                -Message ("Startup mode for {0} is {1}." -f $friendly, $startup) `
                -Recommendation ("Set the {0} service startup type to Automatic." -f $friendly) `
                -Exploitation $exploitationText `
                -Remediation $remediationText

        }
        else {

            fncTestMessage ("{0} configured for automatic startup." -f $friendly) "proten"
        }

        # ------------------------------------------------------------
        # Binary Path Inspection
        # ------------------------------------------------------------

        $binary = $svcInfo.PathName

        if ($binary -and ($binary -notmatch "System32")) {

            $exploitationText = @"
The $friendly service binary path does not reference the expected System32
location.

Unexpected service binary paths may indicate:

- Service binary hijacking
- Malicious replacement
- Unsafe custom configuration
- Persistence via service abuse

Security-sensitive services should run from trusted, validated paths.
"@

            $remediationText = @"
Validate the service binary path.

Recommended actions:

1) Confirm the path matches the approved baseline.
2) Verify the file is signed and trusted.
3) Investigate recent service configuration changes.
4) Restore the expected binary path if tampering is confirmed.
"@

            fncTestMessage ("Suspicious service binary path: {0}" -f $binary) "specpriv"

            fncSubmitFinding `
                -Id ("SERVICE-" + (fncShortHashTag ($name + "_PATH"))) `
                -Category "Persistence" `
                -Title ("{0} Service Binary Path Suspicious" -f $friendly) `
                -Severity "High" `
                -Status "Detected" `
                -Message ("Unexpected binary path detected: {0}" -f $binary) `
                -Recommendation "Validate the service binary location." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }
        else {

            fncTestMessage ("{0} binary path appears expected." -f $friendly) "active"
        }

        # ------------------------------------------------------------
        # Registry Service Configuration
        # ------------------------------------------------------------

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"

        try {

            $reg = Get-ItemProperty -Path $regPath

            if ($reg.Start -eq 4) {

                $exploitationText = @"
Registry configuration shows the $friendly service is disabled.

Attackers commonly modify service startup values in the registry
to prevent defensive services from starting.

This can suppress protections or telemetry across reboots.
"@

                $remediationText = @"
Review and correct the registry configuration for the $friendly service.

Recommended actions:

1) Restore the expected startup value.
2) Confirm the service starts correctly.
3) Investigate who or what changed the registry setting.
4) Monitor for future service configuration tampering.
"@

                fncTestMessage ("Registry indicates service disabled: {0}" -f $friendly) "specpriv"

                fncSubmitFinding `
                    -Id ("SERVICE-" + (fncShortHashTag ($name + "_REG_DISABLED"))) `
                    -Category "Defense Evasion" `
                    -Title ("{0} Service Disabled via Registry" -f $friendly) `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("Registry configuration shows {0} disabled." -f $friendly) `
                    -Recommendation "Review service registry configuration." `
                    -Exploitation $exploitationText `
                    -Remediation $remediationText
            }

        }
        catch {

            fncTestMessage ("Unable to inspect registry configuration for {0}" -f $friendly) "warning"
        }

        # ------------------------------------------------------------
        # Recovery Configuration Check
        # ------------------------------------------------------------

        try {

            $recovery = sc.exe qfailure $name

            if ($recovery -notmatch "RESTART") {

                fncTestMessage ("Service recovery not configured: {0}" -f $friendly) "warning"
            }
            else {

                fncTestMessage ("Service recovery configured for: {0}" -f $friendly) "active"
            }

        }
        catch {

            fncTestMessage ("Recovery configuration could not be inspected for {0}" -f $friendly) "warning"
        }

    }

}

Export-ModuleMember -Function @("fncCheckSecurityCenterServiceState", "fncGetMappings_SECURITY_CENTER_SERVICE_CHECK")