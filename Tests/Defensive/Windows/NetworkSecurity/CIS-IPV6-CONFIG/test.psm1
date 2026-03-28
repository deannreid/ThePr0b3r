# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{
    MitreAttack = @(
        [pscustomobject]@{ Id = "TA0005"; Name = "Defense Evasion"; Tactic = ""; Url = "https://attack.mitre.org/tactics/TA0005/" }
    )
    CWE = @(
        [pscustomobject]@{ Id = "CWE-923"; Name = "Improper Restriction of Communication Channel to Intended Endpoints"; Url = "https://cwe.mitre.org/data/definitions/923.html" }
    )
    Nist = @(
        [pscustomobject]@{ Id = "CM-7"; Name = "Least Functionality"; Url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }
    )
    CIS = @(
        [pscustomobject]@{ Id = "18.5.6.2"; Name = "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"; Version = "3.0.0"; BenchmarkId = "CIS Microsoft Windows 10 Enterprise"; Description = "Set to Highest protection to prevent IPv6 packet spoofing and source routing abuse." }
    )
}

function fncGetMappings_CIS_IPV6_CONFIG { return $script:Mappings }

# ================================================================
# Function: fncCheckIPv6Configuration
# Purpose : Detect IPv6 enablement, infrastructure capability,
#           and common IPv6 attack surface exposure
# Notes   : Adds checks relevant to real-world abuse paths such as
#           rogue RA, DHCPv6 / WPAD relay exposure, tunnelling
#           adapters, and unmanaged dual-stack posture.
# ================================================================
function fncCheckIPv6Configuration {

    fncSafeSectionHeader "IPv6 Network Configuration Assessment"

    $Risk = "Low"
    $RiskReason = "Enumerates IPv6 routes, adapter bindings, tunnelling interfaces, and performs outbound IPv6 connectivity checks which may generate minimal network telemetry"

    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Evaluating IPv6 routing, connectivity, adapter posture, and attack surface exposure..." "info"
    Write-Host ""

    $testId = "CIS-IPV6-CONFIG"

    $infraSupportsIPv6 = $false
    $ipv6Connectivity = $false
    $issueCount = 0
    $evidence = @()

    $ipv6EnabledAdapters = @()
    $tunnelAdapters = @()
    $defaultGatewayRoutes = @()
    $linkLocalOnlyRoutes = $false
    $dhcpv6Likely = $false
    $rogueRaRisk = $false
    $wpadRelayRisk = $false
    $pivotRisk = $false
    $dualStackUnmanagedRisk = $false

    # ------------------------------------------------------------
    # Narratives
    # ------------------------------------------------------------
    $exploitationText = @"
If IPv6 is enabled on endpoints while the organisation does not actively manage or monitor IPv6, attackers may abuse this to bypass security controls that only inspect IPv4 traffic.

Common exploitation paths include:

1) Rogue Router Advertisement (RA) attacks
Attackers on the same segment broadcast malicious IPv6 Router Advertisements.
Windows systems may auto-configure IPv6 addressing and a default route using SLAAC.
This can position the attacker as a man-in-the-middle gateway.

2) DHCPv6 / WPAD relay abuse
Tools such as mitm6 can respond to DHCPv6 and coerce victims into using attacker-controlled name resolution or WPAD infrastructure.
Victims may then authenticate via NTLM, enabling relay to SMB / LDAP / HTTP using ntlmrelayx.

3) IPv6 bypass of IPv4-only controls
If IPv6 is present but unmonitored, attackers may establish outbound C2 or internal lateral movement channels over IPv6 while avoiding IPv4-focused controls.

4) Automatic tunnelling abuse
Windows may expose IPv6 through transitional mechanisms such as Teredo, ISATAP, or 6to4.
These can provide covert routing or alternate egress paths.

5) IPv6-based pivoting
A compromised host with unmanaged IPv6 may be used to route or proxy traffic internally using dual-stack behaviour, tunnelling, or rogue services.
"@

    $remediationText = @"
Recommended hardening:

- If IPv6 is not operationally required, disable IPv6 on all network adapters.
- If IPv6 is required, ensure routers, firewalls, IDS/IPS, DNS, DHCPv6, and monitoring all support and inspect IPv6.
- Disable unnecessary IPv6 transition technologies such as Teredo, ISATAP, and 6to4.
- Monitor for rogue Router Advertisements and DHCPv6 abuse.
- Reduce NTLM usage and disable WPAD where not required.
- Disable LLMNR / NetBIOS and enforce SMB signing to reduce relay exposure.
- Apply Group Policy to enforce consistent IPv6 posture across the fleet.
"@

    # ==========================================================
    # Registry Check: DisabledComponents
    # If IPv6 has been disabled globally via registry we can
    # short-circuit the rest of the checks immediately.
    # HKLM\...\Tcpip6\Parameters\DisabledComponents:
    #   0xFF (255) = all IPv6 components disabled
    #   bit 0x01   = tunnel interfaces disabled
    #   bit 0x10   = non-tunnel interfaces disabled
    #   both set   = effectively fully disabled
    # ==========================================================
    fncTestMessage "Checking registry for global IPv6 disable flag..." "info"

    $ipv6RegDisabled  = $false
    $ipv6RegRawValue  = $null

    try {
        $ipv6RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (Test-Path -LiteralPath $ipv6RegPath -ErrorAction SilentlyContinue) {
            $ipv6RegKey = Get-ItemProperty -LiteralPath $ipv6RegPath -Name "DisabledComponents" -ErrorAction SilentlyContinue
            if ($null -ne $ipv6RegKey -and $null -ne $ipv6RegKey.DisabledComponents) {
                $ipv6RegRawValue = [int]$ipv6RegKey.DisabledComponents
                # 0xFF = all disabled; or bits 0x01 (tunnel) + 0x10 (non-tunnel) both set
                $ipv6RegDisabled = ($ipv6RegRawValue -eq 0xFF) -or
                                   (($ipv6RegRawValue -band 0x11) -eq 0x11)
            }
        }
    }
    catch {
        fncTestMessage "Could not read Tcpip6 registry key." "warning"
        $evidence += "Tcpip6RegistryReadFailed=True"
    }

    if ($ipv6RegDisabled) {

        $regValueHex = "0x{0:X2}" -f $ipv6RegRawValue
        fncTestMessage ("IPv6 disabled via registry. DisabledComponents={0}" -f $regValueHex) "proten"
        $evidence += ("Tcpip6DisabledComponents={0}" -f $regValueHex)

        fncSubmitFinding `
            -Id ("IPV6-" + (fncShortHashTag "REGISTRY_DISABLED")) `
            -Title "IPv6 Disabled via Registry" `
            -Category "Network Security" `
            -Severity "Info" `
            -Status "Configured" `
            -Message ("IPv6 has been disabled globally via the registry (DisabledComponents={0}). The system is not exposed to IPv6 attack surface." -f $regValueHex) `
            -Recommendation "No action required. Ensure this setting is enforced via Group Policy to prevent accidental re-enablement." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    fncTestMessage "DisabledComponents not set or IPv6 not fully disabled via registry -- continuing checks." "info"
    Write-Host ""

    # ==========================================================
    # IPv6 Route Inspection
    # ==========================================================
    fncTestMessage "Inspecting IPv6 routing table..." "info"

    try {

        $ipv6Routes = Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue

        if ($ipv6Routes) {

            fncTestMessage "IPv6 routes detected." "active"

            foreach ($r in $ipv6Routes) {

                $evidence += ("Route={0}->{1}" -f $r.DestinationPrefix, $r.NextHop)

                if ($r.DestinationPrefix -eq "::/0") {
                    $defaultGatewayRoutes += ("DefaultRoute={0}" -f $r.NextHop)
                }

                if ($r.NextHop -and $r.NextHop -ne "::" -and $r.NextHop -notmatch "^fe80:") {
                    $infraSupportsIPv6 = $true
                }

                if ($r.NextHop -match "^fe80:") {
                    $linkLocalOnlyRoutes = $true
                }
            }

            if ($defaultGatewayRoutes.Count -gt 0) {
                fncTestMessage ("IPv6 default route(s) detected: {0}" -f $defaultGatewayRoutes.Count) "active"
            }

            if ($linkLocalOnlyRoutes -and -not $infraSupportsIPv6) {
                fncTestMessage "Only link-local IPv6 routing observed." "warning"
            }
        }
        else {
            fncTestMessage "No IPv6 routes detected." "warning"
        }

    }
    catch {
        fncTestMessage "Failed to inspect IPv6 routing table." "warning"
        $evidence += "IPv6RouteInspectionFailed=True"
    }

    Write-Host ""

    # ==========================================================
    # IPv6 Connectivity Test
    # ==========================================================
    fncTestMessage "Testing outbound IPv6 connectivity..." "info"

    $targets = @(
        "2606:4700:4700::1111",
        "2001:4860:4860::8888"
    )

    foreach ($target in $targets) {

        try {

            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($target, 53)

            if ($client.Connected) {

                fncTestMessage ("IPv6 connectivity confirmed to {0}" -f $target) "active"
                $ipv6Connectivity = $true
                $infraSupportsIPv6 = $true
                $client.Close()

                $evidence += ("IPv6Connectivity={0}" -f $target)
                break
            }

        }
        catch {}
    }

    if (-not $ipv6Connectivity) {
        fncTestMessage "No outbound IPv6 connectivity detected." "warning"
        $evidence += "IPv6Connectivity=None"
    }

    Write-Host ""

    # ==========================================================
    # Adapter Enumeration
    # ==========================================================
    fncTestMessage "Enumerating network adapters..." "info"

    try {

        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object Name

        foreach ($adapter in $adapters) {

            try {

                $ipv6Binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                $ipv6Enabled = $false

                if ($ipv6Binding -and $ipv6Binding.Enabled) {
                    $ipv6Enabled = $true
                    $ipv6EnabledAdapters += $adapter.Name
                }

                $evidence += ("Adapter={0} Status={1} IPv6Enabled={2}" -f $adapter.Name, $adapter.Status, $ipv6Enabled)

                if ($ipv6Enabled -and -not $infraSupportsIPv6) {

                    $issueCount++
                    $dualStackUnmanagedRisk = $true

                    $summary = "IPv6 enabled on adapter '$($adapter.Name)' but no working IPv6 infrastructure was detected."
                    fncTestMessage $summary "specpriv"

                    fncSubmitFinding `
                        -Id ("IPV6-" + (fncShortHashTag ("NO_INFRA_" + $adapter.Name))) `
                        -Title "IPv6 Enabled Without Infrastructure Support" `
                        -Category "Network Security" `
                        -Severity "Medium" `
                        -Status "Detected" `
                        -Message $summary `
                        -Recommendation "Disable IPv6 on adapters if the organisation does not support IPv6 networking." `
                        -Evidence $evidence `
                        -SourceTests @($testId) `
                        -Exploitation $exploitationText `
                        -Remediation $remediationText
                }
                elseif ($ipv6Enabled) {
                    fncTestMessage ("IPv6 enabled on adapter: {0}" -f $adapter.Name) "active"
                }
                else {
                    fncTestMessage ("IPv6 disabled on adapter: {0}" -f $adapter.Name) "proten"
                }

            }
            catch {
                fncTestMessage ("Failed to inspect adapter: {0}" -f $adapter.Name) "warning"
            }
        }

    }
    catch {
        fncTestMessage "Failed to enumerate network adapters." "warning"
        $evidence += "AdapterEnumerationFailed=True"
    }

    Write-Host ""

    # ==========================================================
    # Transition / Tunnel Interface Inspection
    # ==========================================================
    fncTestMessage "Inspecting IPv6 transition and tunnel interfaces..." "info"

    try {

        $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue

        foreach ($a in $allAdapters) {

            $desc = [string]$a.InterfaceDescription
            $name = [string]$a.Name

            if ($desc -match "Teredo|ISATAP|6to4|Tunnel" -or $name -match "Teredo|ISATAP|6to4|Tunnel") {
                $tunnelAdapters += $name
                $evidence += ("TunnelAdapter={0}" -f $name)
            }
        }

        if ($tunnelAdapters.Count -gt 0) {
            $pivotRisk = $true
            fncTestMessage ("IPv6 tunnel / transition adapters detected: {0}" -f ($tunnelAdapters -join ", ")) "warning"
        }
        else {
            fncTestMessage "No obvious IPv6 transition adapters detected." "proten"
        }

    }
    catch {
        fncTestMessage "Unable to inspect transition adapter state." "warning"
        $evidence += "TunnelInspectionFailed=True"
    }

    Write-Host ""

    # ==========================================================
    # DHCPv6 / WPAD Relay Exposure Heuristics
    # ==========================================================
    fncTestMessage "Assessing DHCPv6 / WPAD relay exposure signals..." "info"

    try {

        $dhcpv6RegistryPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
        )

        foreach ($path in $dhcpv6RegistryPaths) {
            if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) {
                $evidence += ("RegistryPathPresent={0}" -f $path)
            }
        }

        if ($ipv6EnabledAdapters.Count -gt 0 -and ($linkLocalOnlyRoutes -or $defaultGatewayRoutes.Count -gt 0)) {
            $dhcpv6Likely = $true
        }

        # WPAD relay exposure heuristic:
        # IPv6 enabled + no confirmed managed infra OR link-local/default route only + NTLM environments often exposed
        if ($ipv6EnabledAdapters.Count -gt 0 -and ($dhcpv6Likely -or -not $infraSupportsIPv6)) {
            $wpadRelayRisk = $true
            fncTestMessage "IPv6 posture may expose DHCPv6 / WPAD relay attack surface." "warning"
            $evidence += "WPADRelayRisk=True"
        }
        else {
            fncTestMessage "No obvious DHCPv6 / WPAD relay exposure signal detected from current checks." "info"
        }

    }
    catch {
        fncTestMessage "Unable to assess DHCPv6 / WPAD relay exposure." "warning"
        $evidence += "WPADExposureAssessmentFailed=True"
    }

    Write-Host ""

    # ==========================================================
    # Rogue RA Exposure Heuristics
    # ==========================================================
    fncTestMessage "Assessing rogue Router Advertisement exposure..." "info"

    if ($ipv6EnabledAdapters.Count -gt 0 -and -not $infraSupportsIPv6) {
        $rogueRaRisk = $true
    }

    if ($ipv6EnabledAdapters.Count -gt 0 -and $linkLocalOnlyRoutes -and -not $ipv6Connectivity) {
        $rogueRaRisk = $true
    }

    if ($rogueRaRisk) {
        fncTestMessage "IPv6-enabled hosts with unmanaged or link-local-only posture may be exposed to rogue RA abuse." "warning"
        $evidence += "RogueRARisk=True"
    }
    else {
        fncTestMessage "No obvious rogue RA exposure signal detected from current checks." "info"
    }

    Write-Host ""

    # ==========================================================
    # Consolidated IPv6 Attack Surface Findings
    # ==========================================================
    if ($rogueRaRisk) {

        $issueCount++

        fncSubmitFinding `
            -Id ("IPV6-" + (fncShortHashTag "ROGUE_RA_RISK")) `
            -Title "IPv6 Rogue Router Advertisement Exposure" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message "IPv6 appears enabled in a posture that may allow rogue Router Advertisement abuse." `
            -Recommendation "Disable unused IPv6 or enforce managed RA controls and IPv6 monitoring." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

    if ($wpadRelayRisk) {

        $issueCount++

        fncSubmitFinding `
            -Id ("IPV6-" + (fncShortHashTag "WPAD_DHCPV6_RELAY_RISK")) `
            -Title "IPv6 DHCPv6 / WPAD Relay Exposure" `
            -Category "Network Security" `
            -Severity "High" `
            -Status "Detected" `
            -Message "IPv6 posture indicates potential exposure to DHCPv6 / WPAD coercion and NTLM relay attack paths." `
            -Recommendation "Disable unused IPv6, harden WPAD usage, reduce NTLM dependence, and monitor DHCPv6 abuse." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

    if ($pivotRisk) {

        $issueCount++

        fncSubmitFinding `
            -Id ("IPV6-" + (fncShortHashTag "TUNNEL_PIVOT_RISK")) `
            -Title "IPv6 Transition / Tunnel Attack Surface Present" `
            -Category "Network Security" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "IPv6 transition or tunnel interfaces were detected, which may provide alternate routing or pivot paths." `
            -Recommendation "Disable unnecessary IPv6 transition technologies such as Teredo, ISATAP, and 6to4." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

    if ($ipv6EnabledAdapters.Count -gt 0 -and $infraSupportsIPv6 -and -not $rogueRaRisk -and -not $wpadRelayRisk -and -not $pivotRisk) {
        fncTestMessage "IPv6 is enabled and appears supported by infrastructure." "proten"
    }

    Write-Host ""

    # ==========================================================
    # Summary
    # ==========================================================
    if ($issueCount -eq 0) {

        fncTestMessage "IPv6 configuration appears aligned with infrastructure capability and no obvious attack surface signals were identified." "proten"

        fncSubmitFinding `
            -Id ("IPV6-" + (fncShortHashTag "CONFIG_OK")) `
            -Title "IPv6 Configuration Acceptable" `
            -Category "Network Security" `
            -Severity "Info" `
            -Status "Configured" `
            -Message "IPv6 configuration appears aligned with infrastructure capability and no obvious unmanaged attack surface was identified." `
            -Recommendation "No action required." `
            -Evidence $evidence `
            -SourceTests @($testId) `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    fncTestMessage ("Detected {0} IPv6 configuration issue(s)." -f $issueCount) "warning"
}

Export-ModuleMember -Function @("fncCheckIPv6Configuration", "fncGetMappings_CIS_IPV6_CONFIG")