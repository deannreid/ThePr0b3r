# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1059"; Name = "Command and Scripting Interpreter"; Tactic = "Defense Evasion"; Url = "" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-778"; Name = "Insufficient Logging"; Url = "" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "AU-2"; Name = "Audit Events"; Url = "" }
        [pscustomobject]@{ Id = "AU-12"; Name = "Audit Record Generation"; Url = "" }
    )
    CIS = @(
    )
}

function fncGetMappings_COMMANDLINE_LOGGING_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckCommandlineLogging
# Purpose : Identify gaps in command-line and PowerShell logging
# Notes   : Red-team visibility assessment of host telemetry
# ================================================================
function fncCheckCommandlineLogging {

    fncPrintSectionHeader "Command-Line & PowerShell Logging Exposure"

    $Risk = "Low"
    $RiskReason = "Performs read-only checks of Windows audit policy, registry policy keys, and event log configuration"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Assessing command execution visibility..." "info"

# ------------------------------------------------------------
# Process Creation Auditing
# ------------------------------------------------------------

$processAudit = $false

try {

    $audit = auditpol /get /subcategory:"Process Creation" 2>$null

    if ($audit -match "Success") {
        $processAudit = $true
    }

} catch {}

if ($processAudit) {

    fncTestMessage "Process creation auditing enabled." "proten"

} else {

    fncTestMessage "Process creation auditing not enabled." "specpriv"

    $exploitationText = @"
Without process creation auditing, attackers can execute tools such as cmd.exe, powershell.exe, wmic, rundll32, and other LOLBINs without generating event 4688 telemetry. This significantly reduces defender visibility into command execution activity.
"@

    $remediationText = @"
Enable 'Audit Process Creation' under Advanced Audit Policy Configuration.

Policy Path:
Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation

Ensure Success auditing is enabled.
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "PROCESS_AUDIT_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "Process Creation Logging Disabled" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "Audit Process Creation events are not enabled." `
        -Recommendation "Enable Process Creation auditing." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

# ------------------------------------------------------------
# Command Line Logging
# ------------------------------------------------------------

$cmdLineEnabled = $false
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

try {

    $value = Get-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue

    if ($value.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        $cmdLineEnabled = $true
    }

} catch {}

if ($cmdLineEnabled) {

    fncTestMessage "Command line logging enabled." "proten"

} else {

    fncTestMessage "Command line arguments not captured." "specpriv"

    $exploitationText = @"
Without command-line logging enabled, defenders will see the process start but not the arguments. Attackers can hide encoded PowerShell payloads, malicious command parameters, or credential harvesting commands.
"@

    $remediationText = @"
Enable the 'Include command line in process creation events' policy.

Policy Path:
Computer Configuration -> Administrative Templates -> System -> Audit Process Creation

Enable the policy and ensure event 4688 captures command-line arguments.
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "CMDLINE_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "Command Line Logging Disabled" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "Process command-line arguments are not recorded." `
        -Recommendation "Enable 'Include command line in process creation events'." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

# ------------------------------------------------------------
# PowerShell Script Block Logging
# ------------------------------------------------------------

$psScriptLogging = $false
$psReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

try {

    $val = Get-ItemProperty -Path $psReg -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue

    if ($val.EnableScriptBlockLogging -eq 1) {
        $psScriptLogging = $true
    }

} catch {}

if ($psScriptLogging) {

    fncTestMessage "PowerShell Script Block logging enabled." "proten"

} else {

    fncTestMessage "PowerShell Script Block logging disabled." "specpriv"

    $exploitationText = @"
Script Block Logging records the actual PowerShell code executed, even when obfuscated. Without it, attackers can execute in-memory PowerShell payloads that leave minimal forensic evidence.
"@

    $remediationText = @"
Enable PowerShell Script Block Logging.

Policy Path:
Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "PS_SCRIPTBLOCK_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "PowerShell Script Block Logging Disabled" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "PowerShell script block logging is not enabled." `
        -Recommendation "Enable Script Block Logging." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

# ------------------------------------------------------------
# PowerShell Module Logging
# ------------------------------------------------------------

$psModuleLogging = $false
$moduleReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

try {

    $val = Get-ItemProperty -Path $moduleReg -Name EnableModuleLogging -ErrorAction SilentlyContinue

    if ($val.EnableModuleLogging -eq 1) {
        $psModuleLogging = $true
    }

} catch {}

if ($psModuleLogging) {

    fncTestMessage "PowerShell module logging enabled." "proten"

} else {

    fncTestMessage "PowerShell module logging disabled." "warning"

    $exploitationText = @"
Module logging records when PowerShell modules are loaded. Offensive frameworks frequently load modules such as PowerView, Nishang, or Empire components. Without this telemetry, detection becomes harder.
"@

    $remediationText = @"
Enable PowerShell Module Logging.

Policy Path:
Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on Module Logging
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "PS_MODULE_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "PowerShell Module Logging Disabled" `
        -Severity "Medium" `
        -Status "Likely Exposed" `
        -Message "PowerShell module logging is disabled." `
        -Recommendation "Enable PowerShell module logging." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

# ------------------------------------------------------------
# PowerShell Operational Log
# ------------------------------------------------------------

try {

    $log = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational"

    if ($log.IsEnabled) {

        fncTestMessage "PowerShell operational log enabled." "active"

    } else {

        fncTestMessage "PowerShell operational log disabled." "specpriv"

        $exploitationText = @"
The PowerShell Operational log records PowerShell execution telemetry. If disabled, attackers may run scripts without generating event logs that defenders rely on for detection.
"@

        $remediationText = @"
Enable the Microsoft-Windows-PowerShell/Operational log in Event Viewer or via GPO to ensure PowerShell activity is recorded.
"@

        fncSubmitFinding `
            -Id ("CMDLOG-" + (fncShortHashTag "PS_OPLOG_DISABLED")) `
            -Category "Defense Evasion" `
            -Title "PowerShell Operational Logging Disabled" `
            -Severity "Medium" `
            -Status "Likely Exposed" `
            -Message "PowerShell operational event log is disabled." `
            -Recommendation "Enable the Microsoft-Windows-PowerShell/Operational log." `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

} catch {

    fncTestMessage "Unable to inspect PowerShell event logs." "warning"
}

# ------------------------------------------------------------
# PowerShell Transcription Logging
# ------------------------------------------------------------

$transcriptionEnabled = $false
$transcriptReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

try {

    $val = Get-ItemProperty -Path $transcriptReg -Name EnableTranscripting -ErrorAction SilentlyContinue

    if ($val.EnableTranscripting -eq 1) {
        $transcriptionEnabled = $true
    }

} catch {}

if ($transcriptionEnabled) {

    fncTestMessage "PowerShell transcription logging enabled." "proten"

} else {

    fncTestMessage "PowerShell transcription logging disabled." "warning"

    $exploitationText = @"
PowerShell transcription captures full command transcripts for investigative analysis. Without transcription, responders lose detailed command history.
"@

    $remediationText = @"
Enable PowerShell Transcription Logging via Group Policy and configure a secure transcript storage location.
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "PS_TRANSCRIPTION_DISABLED")) `
        -Category "Defense Evasion" `
        -Title "PowerShell Transcription Logging Disabled" `
        -Severity "Medium" `
        -Status "Likely Exposed" `
        -Message "PowerShell transcription logging is disabled." `
        -Recommendation "Enable PowerShell transcription logging." `
        -Exploitation $exploitationText `
        -Remediation $remediationText
}

# ------------------------------------------------------------
# PowerShell Downgrade Attack Exposure
# ------------------------------------------------------------

$psv2Enabled = $false

try {

    $feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue

    if ($feature.State -eq "Enabled") {
        $psv2Enabled = $true
    }

} catch {}

try {

    $psEngine = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -ErrorAction SilentlyContinue

    if ($psEngine.PowerShellVersion -match "^2") {
        $psv2Enabled = $true
    }

} catch {}

if ($psv2Enabled) {

    fncTestMessage "PowerShell v2 engine present. Downgrade attacks possible." "specpriv"

    $exploitationText = @"
PowerShell v2 lacks modern security protections including AMSI and advanced logging. Attackers can execute 'powershell.exe -version 2' to bypass many defensive controls.
"@

    $remediationText = @"
Remove the PowerShell v2 feature from Windows systems unless absolutely required for legacy applications.
"@

    fncSubmitFinding `
        -Id ("CMDLOG-" + (fncShortHashTag "POWERSHELL_V2_PRESENT")) `
        -Category "Defense Evasion" `
        -Title "PowerShell Downgrade Attack Possible" `
        -Severity "High" `
        -Status "Likely Exposed" `
        -Message "PowerShell v2 engine present on host." `
        -Recommendation "Remove PowerShell v2." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

} else {

    fncTestMessage "PowerShell v2 engine not installed." "proten"
}

# ------------------------------------------------------------
# LOLBIN Telemetry Exposure
# ------------------------------------------------------------

$lolbins = @(
"powershell.exe",
"cmd.exe",
"wmic.exe",
"rundll32.exe",
"mshta.exe",
"certutil.exe",
"regsvr32.exe"
)

fncTestMessage "Assessing visibility of common LOLBIN execution tools..." "info"

foreach ($bin in $lolbins) {

    fncTestMessage ("Common LOLBIN frequently abused by attackers: {0}" -f $bin) "active"
}

fncTestMessage "https://attack.mitre.org/techniques/T1059/" "link"
fncTestMessage "https://attack.mitre.org/techniques/T1218/" "link"

}

Export-ModuleMember -Function @("fncCheckCommandlineLogging", "fncGetMappings_COMMANDLINE_LOGGING_CHECK")