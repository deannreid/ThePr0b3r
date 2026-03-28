# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1047"; Name = "Windows Management Instrumentation"; Tactic = "Execution"; Url = "https://attack.mitre.org/techniques/T1047/" }
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

function fncGetMappings_WMI_LOGGING_ENABLED { return $script:Mappings }

# ================================================================
# Function: fncCheckWMILogging
# Purpose : Validate WMI Activity logging configuration
# Notes   : Ensures the WMI Activity Operational log is enabled
#           for monitoring WMI-based attacker activity
# ================================================================
function fncCheckWMILogging {

    fncPrintSectionHeader "WMI Activity Logging Validation"

    $Risk = "Low"
    $RiskReason = "Performs read-only enumeration of Windows event log configuration"
    fncPrintRisk $Risk $RiskReason

    $testId = "WMI-LOGGING-ENABLED"

    fncTestMessage "Checking WMI Activity logging configuration..." "info"

    # ------------------------------------------------------------
    # Query WMI Activity Event Log
    # ------------------------------------------------------------

    $logName = "Microsoft-Windows-WMI-Activity/Operational"
    $log = $null

    try {

        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop

        fncTestMessage "WMI Activity log successfully queried." "active"

    }
    catch {

        $exploitationText = @"
The WMI Activity Operational event log could not be located.

Attackers frequently abuse Windows Management Instrumentation (WMI)
for execution, lateral movement, and persistence.

If the WMI Activity log is missing or unavailable, malicious WMI
activity may occur without generating forensic evidence.

This reduces visibility into attacker techniques such as:

- Remote command execution via WMI
- WMI event subscription persistence
- Lateral movement using WMI
"@

        $remediationText = @"
Ensure the WMI Activity Operational log exists and is available.

Recommended actions:

1) Verify the event log channel is present.
2) Restore the WMI logging configuration if missing.
3) Ensure event forwarding or SIEM ingestion includes WMI logs.
4) Monitor for configuration changes affecting WMI logging.
"@

        fncTestMessage "Unable to query WMI Activity event log." "specpriv"

        fncSubmitFinding `
            -Id ("WMI-" + (fncShortHashTag "LOG_NOT_FOUND")) `
            -Category "Defense Evasion" `
            -Title "WMI Activity Event Log Not Found" `
            -Severity "High" `
            -Status "Detected" `
            -Message "The WMI Activity Operational log could not be located." `
            -Recommendation "Verify system logging configuration." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Determine Logging State
    # ------------------------------------------------------------

    $enabled = $false

    try {

        if ($log.IsEnabled) {
            $enabled = $true
        }

        fncTestMessage ("WMI Activity log enabled state: {0}" -f $log.IsEnabled) "active"

    }
    catch {

        fncTestMessage "Unable to determine WMI Activity log state." "warning"
    }

    # ------------------------------------------------------------
    # Logging Enabled
    # ------------------------------------------------------------

    if ($enabled) {

        fncTestMessage "WMI Activity logging is enabled." "proten"

        fncSubmitFinding `
            -Id ("WMI-" + (fncShortHashTag "LOG_ENABLED")) `
            -Category "Defense Evasion" `
            -Title "WMI Activity Logging Enabled" `
            -Severity "Info" `
            -Status "Protected" `
            -Message "WMI Activity Operational logging is enabled." `
            -Recommendation "Maintain WMI logging configuration." `
            -Exploitation "WMI activity will generate audit events for security monitoring." `
            -Remediation "No remediation required."

        # ------------------------------------------------------------
        # Optional: Log Size Check
        # ------------------------------------------------------------

        try {

            $logSizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)

            fncTestMessage ("WMI Activity log size detected: {0} MB" -f $logSizeMB) "active"

            if ($logSizeMB -lt 32) {

                $exploitationText = @"
The WMI Activity log size is small.

Small event logs can allow attackers to overwrite forensic
evidence more quickly.

Attackers may generate large volumes of events to push
malicious activity out of the log retention window.
"@

                $remediationText = @"
Increase the WMI Activity Operational log size.

Recommended actions:

1) Increase the maximum log size.
2) Ensure logs are forwarded to a SIEM or centralized log store.
3) Monitor for suspicious log clearing or excessive event volume.
"@

                fncTestMessage ("WMI Activity log size appears small: {0}MB" -f $logSizeMB) "warning"

                fncSubmitFinding `
                    -Id ("WMI-" + (fncShortHashTag "LOG_SIZE_SMALL")) `
                    -Category "Defense Evasion" `
                    -Title "WMI Activity Log Size Too Small" `
                    -Severity "Medium" `
                    -Status "Detected" `
                    -Message ("WMI Activity log size is only {0}MB." -f $logSizeMB) `
                    -Recommendation "Increase log size to retain sufficient security telemetry." `
                    -Exploitation $exploitationText `
                    -Remediation $remediationText
            }

        }
        catch {

            fncTestMessage "Unable to determine WMI Activity log size." "warning"
        }

        return
    }

    # ------------------------------------------------------------
    # Logging Disabled
    # ------------------------------------------------------------

    $exploitationText = @"
WMI Activity logging is disabled.

Attackers frequently abuse WMI for execution, persistence,
and lateral movement within Windows environments.

Without WMI Activity logging enabled, malicious WMI activity
may occur without generating detectable security events.

This reduces the ability to detect:

- WMI remote command execution
- WMI persistence mechanisms
- Lateral movement via WMI
"@

    $remediationText = @"
Enable WMI Activity logging.

Recommended actions:

1) Enable the event log:
   Microsoft-Windows-WMI-Activity/Operational

2) Ensure the log is monitored by security tools.

3) Forward the log to centralized monitoring platforms.

4) Periodically verify logging configuration remains enabled.
"@

    fncTestMessage "WMI Activity logging is NOT enabled." "specpriv"

    fncSubmitFinding `
        -Id ("WMI-" + (fncShortHashTag "LOG_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "WMI Activity Logging Disabled" `
        -Severity "High" `
        -Status "Detected" `
        -Message "WMI Activity Operational log is disabled." `
        -Recommendation "Enable WMI Activity logging for monitoring." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

Export-ModuleMember -Function @("fncCheckWMILogging", "fncGetMappings_WMI_LOGGING_ENABLED")