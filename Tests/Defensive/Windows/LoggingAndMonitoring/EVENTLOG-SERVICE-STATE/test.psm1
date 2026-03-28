# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/002/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Improper Access Control"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AU-2"; Name = "Audit Events"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_EVENTLOG_SERVICE_STATE { return $script:Mappings }

# ================================================================
# Function: fncCheckEventLogServiceState
# Purpose : Validate Windows Event Log service state and startup
# Notes   : Ensures EventLog service is running and correctly
#           configured. Stopping this service prevents logging.
# ================================================================
function fncCheckEventLogServiceState {

    fncPrintSectionHeader "Windows Event Log Service Validation"

    $Risk = "Safe"
    $RiskReason = "Performs read-only service and CIM queries to verify Windows Event Log service configuration"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking Windows Event Log service status..." "info"

# ------------------------------------------------------------
# Query Service
# ------------------------------------------------------------

    $service = $null

    try {

        $service = Get-Service -Name "EventLog" -ErrorAction Stop

        fncTestMessage "EventLog service successfully queried." "active"

    } catch {

        fncTestMessage "Unable to query Windows Event Log service." "specpriv"

$exploitationText = @"
The Windows Event Log service could not be located.

This service is responsible for recording security, system,
and application logging events.

If the Event Log service is missing or tampered with,
attackers may be attempting to disable logging to hide
malicious activity.
"@

$remediationText = @"
Investigate the integrity of the operating system immediately.

Recommended actions:

1) Verify the Windows Event Log service configuration.
2) Restore the service if it has been modified or removed.
3) Validate system integrity using system file checks.
4) Review recent system changes and administrative actions.
"@

        fncSubmitFinding `
            -Id ("EVENTLOG-" + (fncShortHashTag "SERVICE_NOT_FOUND")) `
            -Category "Defense Evasion" `
            -Title "Windows Event Log Service Not Found" `
            -Severity "High" `
            -Status "Detected" `
            -Message "Windows Event Log service could not be located." `
            -Recommendation "Investigate system integrity immediately." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Determine Service State
# ------------------------------------------------------------

    $serviceRunning = $false
    $startupType = "Unknown"

    try {

        if ($service.Status -eq "Running") {
            $serviceRunning = $true
        }

        $wmi = Get-CimInstance Win32_Service -Filter "Name='EventLog'"
        $startupType = $wmi.StartMode

        fncTestMessage ("EventLog startup type detected: {0}" -f $startupType) "active"

    } catch {

        fncTestMessage "Unable to determine EventLog startup configuration." "warning"
    }

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/002/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging" "link"

# ------------------------------------------------------------
# Service Running
# ------------------------------------------------------------

    if ($serviceRunning) {

        fncTestMessage "Windows Event Log service is running." "proten"

    } else {

        fncTestMessage "Windows Event Log service is NOT running." "specpriv"

$exploitationText = @"
The Windows Event Log service is not running.

If logging is disabled, security events such as authentication,
privilege changes, and process execution may not be recorded.

Attackers often stop logging services to prevent their actions
from being captured during post-exploitation activities.
"@

$remediationText = @"
Restart the Windows Event Log service immediately.

Recommended actions:

1) Start the EventLog service.
2) Investigate why the service stopped.
3) Review system logs and security alerts.
4) Ensure security logging is centrally monitored.
"@

        fncSubmitFinding `
            -Id ("EVENTLOG-" + (fncShortHashTag "SERVICE_STOPPED")) `
            -Category "Defense Evasion" `
            -Title "Windows Event Log Service Stopped" `
            -Severity "High" `
            -Status "Detected" `
            -Message "Windows Event Log service is not running." `
            -Recommendation "Restart the Windows Event Log service immediately." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Startup Type Validation
# ------------------------------------------------------------

    if ($startupType -eq "Auto") {

        fncTestMessage "EventLog service startup type is Automatic." "proten"

$exploitationText = @"
The Windows Event Log service is operational and configured to
start automatically.

This ensures security logging remains active across system reboots.
"@

$remediationText = @"
No remediation required.

Maintain current logging configuration and ensure security
events are forwarded to central monitoring infrastructure.
"@

        fncSubmitFinding `
            -Id ("EVENTLOG-" + (fncShortHashTag "SERVICE_HEALTHY")) `
            -Category "Defense Evasion" `
            -Title "Windows Event Log Service Operational" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "Windows Event Log service is running and configured for automatic startup." `
            -Recommendation "Maintain current configuration." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Startup Type Misconfiguration
# ------------------------------------------------------------

    fncTestMessage ("EventLog service startup type is {0}." -f $startupType) "specpriv"

$exploitationText = @"
The Windows Event Log service is not configured for automatic startup.

If the service fails to start during system boot, security logging
may not be available.

Attackers may change service startup configuration to delay
or disable logging across system restarts.
"@

$remediationText = @"
Configure the Windows Event Log service to start automatically.

Recommended actions:

1) Set the EventLog service startup type to Automatic.
2) Verify the service starts correctly during system boot.
3) Ensure logging infrastructure is centrally monitored.
"@

    fncSubmitFinding `
        -Id ("EVENTLOG-" + (fncShortHashTag "STARTUP_NOT_AUTO")) `
        -Category "Defense Evasion" `
        -Title "Windows Event Log Startup Type Misconfigured" `
        -Severity "Medium" `
        -Status "Detected" `
        -Message ("Windows Event Log service startup type is set to '{0}'." -f $startupType) `
        -Recommendation "Configure the EventLog service to start automatically." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

}

Export-ModuleMember -Function @("fncCheckEventLogServiceState", "fncGetMappings_EVENTLOG_SERVICE_STATE")