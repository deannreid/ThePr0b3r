# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "T1562"; Name = "Impair Defenses"; Tactic = "Defense Evasion"; Url = "https://attack.mitre.org/techniques/T1562/004/" }
        [pscustomobject]@{ Id = "TA0008"; Name = "Lateral Movement"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0008/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-284"; Name = "Exposure of Network Services"; Url = "https://cwe.mitre.org/data/definitions/284.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "SC-7"; Name = "Boundary Protection"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
    )
}

function fncGetMappings_FIREWALL_RULE_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckWindowsFirewallConfiguration
# Purpose : Validate Windows Firewall profiles and analyse inbound
#           AND outbound firewall rules
# Notes   : Requires Administrator privileges
# ================================================================
function fncCheckWindowsFirewallConfiguration {

    fncPrintSectionHeader "Windows Firewall Configuration Validation"

    $Risk = "Low"
    $RiskReason = "Performs read-only enumeration of Windows Firewall profiles and rule configuration"
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking Windows Firewall configuration..." "info"

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

        fncTestMessage "Administrator privileges required to inspect firewall configuration." "disabled"

$exploitationText = @"
This validation requires administrative privileges to enumerate Windows Firewall
configuration.

If attackers obtain administrative access they may modify firewall rules
to allow malicious traffic or disable firewall protections entirely.
"@

$remediationText = @"
Run this validation with administrative privileges.

Ensure firewall configuration changes are centrally managed and monitored
through security logging and endpoint monitoring platforms.
"@

        fncSubmitFinding `
            -Id ("FIREWALL-" + (fncShortHashTag "ADMIN_REQUIRED")) `
            -Category "Defense Evasion" `
            -Title "Windows Firewall Check Requires Administrative Privileges" `
            -Severity "Low" `
            -Status "Mixed / Unclear" `
            -Message "Administrator privileges required to enumerate firewall configuration." `
            -Recommendation "Run this check with administrative privileges." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

# ------------------------------------------------------------
# Check Firewall Profiles
# ------------------------------------------------------------

    fncTestMessage "Inspecting firewall profiles..." "info"

    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $disabledProfiles = @()

    foreach ($profile in $profiles) {

        fncTestMessage ("Firewall profile detected: {0}" -f $profile.Name) "active"

        if (-not $profile.Enabled) {

            $disabledProfiles += $profile.Name
        }
    }

    if ($disabledProfiles.Count -eq 0) {

        fncTestMessage "Windows Firewall enabled across Domain, Private, and Public profiles." "proten"

    } else {

        fncTestMessage ("Firewall disabled on profiles: {0}" -f ($disabledProfiles -join ", ")) "specpriv"
    }

# ------------------------------------------------------------
# Enumerate inbound firewall rules
# ------------------------------------------------------------

    fncTestMessage "Enumerating inbound firewall rules..." "info"

    $inboundRules = Get-NetFirewallRule `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -ErrorAction SilentlyContinue

    $inboundPorts = @()

    foreach ($rule in $inboundRules) {

        try {

            fncTestMessage ("Inspecting rule: {0}" -f $rule.DisplayName) "active"

            $portFilter = Get-NetFirewallPortFilter `
                -AssociatedNetFirewallRule $rule `
                -ErrorAction SilentlyContinue

            if (-not $portFilter) { continue }

            $ports = $portFilter.LocalPort

            if (-not $ports) { continue }

            foreach ($port in $ports) {

                if ($port -eq "Any") { continue }

                $portInUse = $false

                $listener = Get-NetTCPConnection `
                    -LocalPort $port `
                    -State Listen `
                    -ErrorAction SilentlyContinue

                if ($listener) {

                    $portInUse = $true

                    fncTestMessage ("Inbound port {0} actively used by a service." -f $port) "active"

                }
                else {

                    fncTestMessage ("Firewall allows inbound port {0} but no active service detected." -f $port) "specpriv"
                }

                $inboundPorts += [PSCustomObject]@{
                    Direction = "Inbound"
                    Rule      = $rule.DisplayName
                    Port      = $port
                    InUse     = $portInUse
                }

            }

        } catch {

            fncTestMessage ("Failed inspecting firewall rule {0}" -f $rule.DisplayName) "warning"
        }
    }

# ------------------------------------------------------------
# Enumerate outbound firewall rules
# ------------------------------------------------------------

    fncTestMessage "Enumerating outbound firewall rules..." "info"

    $outboundRules = Get-NetFirewallRule `
        -Direction Outbound `
        -Action Allow `
        -Enabled True `
        -ErrorAction SilentlyContinue

    $outboundPorts = @()

    foreach ($rule in $outboundRules) {

        try {

            $portFilter = Get-NetFirewallPortFilter `
                -AssociatedNetFirewallRule $rule `
                -ErrorAction SilentlyContinue

            if (-not $portFilter) { continue }

            $ports = $portFilter.RemotePort

            if (-not $ports) { continue }

            foreach ($port in $ports) {

                if ($port -eq "Any") { continue }

                fncTestMessage ("Outbound rule allows traffic to port {0}" -f $port) "active"

                $outboundPorts += [PSCustomObject]@{
                    Direction = "Outbound"
                    Rule      = $rule.DisplayName
                    Port      = $port
                }

            }

        } catch {

            fncTestMessage ("Failed inspecting outbound firewall rule {0}" -f $rule.DisplayName) "warning"
        }
    }

# ------------------------------------------------------------
# References
# ------------------------------------------------------------

    fncTestMessage "https://attack.mitre.org/techniques/T1562/004/" "link"
    fncTestMessage "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/" "link"

# ------------------------------------------------------------
# Analyse inbound ports
# ------------------------------------------------------------

    $unusedPorts = $inboundPorts | Where-Object { $_.InUse -eq $false }

    if ($unusedPorts.Count -gt 0) {

        foreach ($p in $unusedPorts | Select-Object -First 10) {

            fncTestMessage ("Unused inbound firewall port detected: {0} ({1})" -f $p.Port,$p.Rule) "specpriv"
        }

        $portList = ($unusedPorts | ForEach-Object { $_.Port }) -join ", "

$exploitationText = @"
Firewall rules allow inbound traffic to ports where no active service
is listening.

Unused open ports increase the attack surface and may expose systems
if services later bind to those ports.
"@

$remediationText = @"
Review inbound firewall rules and remove unnecessary rules allowing
traffic to unused ports.

Ensure firewall rules match the services actually required.
"@

        fncSubmitFinding `
            -Id ("FIREWALL-" + (fncShortHashTag "UNUSED_PORTS")) `
            -Category "Defense Evasion" `
            -Title "Firewall Allows Unused Inbound Ports" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("Firewall allows inbound ports without active services: {0}" -f $portList) `
            -Recommendation "Remove unused inbound firewall rules." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

    }
    else {

        fncTestMessage "No unnecessary inbound firewall ports detected." "proten"
    }

# ------------------------------------------------------------
# Analyse outbound firewall rules
# ------------------------------------------------------------

    if ($outboundPorts.Count -gt 0) {

        $topOutbound = $outboundPorts |
                       Group-Object Port |
                       Sort-Object Count -Descending |
                       Select-Object -First 10

        foreach ($p in $topOutbound) {

            fncTestMessage ("Outbound traffic permitted to port {0} ({1} rule(s))" -f $p.Name,$p.Count) "active"
        }

    }
    else {

        fncTestMessage "No explicit outbound firewall port rules detected." "proten"
    }

# ------------------------------------------------------------
# Firewall profile finding
# ------------------------------------------------------------

    if ($disabledProfiles.Count -gt 0) {

$exploitationText = @"
One or more Windows Firewall profiles are disabled.

Disabling firewall protections allows unrestricted inbound
and outbound network traffic, significantly increasing the
system's exposure to network-based attacks.
"@

$remediationText = @"
Enable Windows Firewall protection across all network profiles:

- Domain
- Private
- Public

Ensure firewall configuration is centrally managed and monitored.
"@

        fncSubmitFinding `
            -Id ("FIREWALL-" + (fncShortHashTag "PROFILE_DISABLED")) `
            -Category "Defense Evasion" `
            -Title "Windows Firewall Disabled On One Or More Profiles" `
            -Severity "High" `
            -Status "Detected" `
            -Message ("Firewall disabled on profiles: {0}" -f ($disabledProfiles -join ", ")) `
            -Recommendation "Enable firewall protection across all network profiles." `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

}

Export-ModuleMember -Function @("fncCheckWindowsFirewallConfiguration", "fncGetMappings_FIREWALL_RULE_CHECK")