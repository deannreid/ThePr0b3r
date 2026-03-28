# ================================================================
# Module  : UI.Operator.psm1
# ================================================================

#Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------
# Platform detection
# ----------------------------------------------------------------
$script:OperatorIsWindows = $true
try {
    if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
        if ($IsLinux -or $IsMacOS) { $script:OperatorIsWindows = $false }
    }
}
catch {}

# ----------------------------------------------------------------
# Linux security process indicators
# ----------------------------------------------------------------
$script:linuxSecurityProcs = [ordered]@{
    "clamd"         = "ClamAV"
    "freshclam"     = "ClamAV"
    "wazuh-agentd"  = "Wazuh"
    "ossec"         = "OSSEC"
    "falco"         = "Falco"
    "sysdig"        = "Sysdig"
    "osqueryd"      = "osquery"
    "falcon-sensor" = "CrowdStrike Falcon"
    "s1agent"       = "SentinelOne"
    "cbagentd"      = "Carbon Black"
    "cbdefense"     = "Carbon Black"
    "elastic-agent" = "Elastic Agent"
    "filebeat"      = "Elastic Filebeat"
    "auoms"         = "Microsoft Defender for Linux"
    "mdatp"         = "Microsoft Defender for Linux"
}

function fncOperatorRiskColour {
    param([string]$lvl)

    switch ($lvl) {

        "RED" { return [System.ConsoleColor]::Red }
        "AMBER" { return [System.ConsoleColor]::Yellow }

        default { return [System.ConsoleColor]::Green }
    }
}

function fncGetTelemetryCachePath {

    if (
        -not $global:ProberState.PSObject.Properties.Name -contains "Runtime" -or
        -not $global:ProberState.Runtime.RunLogDir
    ) {
        throw "RunLogDir not initialised by runner."
    }

    $root = Join-Path $global:ProberState.Runtime.RunLogDir "Telemetry"

    if (-not (Test-Path $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }

    return (Join-Path $root "operatorTelemetry.json")
}

function fncToLowerSet {
    param($list)

    $out = @()

    foreach ($x in (fncSafeArray $list)) {
        $s = fncSafeString $x
        if ($s) { $out += $s.ToLowerInvariant() }
    }

    return @($out | Sort-Object -Unique)
}

function fncAnyContains {
    param($hay, $needles)

    foreach ($n in (fncSafeArray $needles)) {

        $nl = fncSafeString $n
        if (-not $nl) { continue }

        foreach ($h in (fncSafeArray $hay)) {
            if ($h.ToLowerInvariant() -like "*$($nl.ToLowerInvariant())*") { return $true }
        }
    }

    return $false
}

$script:edrWeights = @{

    # Microsoft
    "Microsoft Defender Antivirus"    = 20
    "Microsoft Defender for Endpoint" = 35

    # Top Tier
    "CrowdStrike Falcon"              = 40
    "SentinelOne"                     = 40
    "Palo Alto Cortex XDR"            = 40
    "VMware Carbon Black"             = 35
    "Trellix Endpoint Security"       = 35

    # Strong Commercial
    "Sophos Intercept X"              = 30
    "Trend Micro Apex One"            = 30
    "Bitdefender GravityZone"         = 30
    "Elastic Endpoint Security"       = 30
    "Check Point Harmony Endpoint"    = 30
    "ESET Protect"                    = 28

    # Visibility / IR Platforms
    "Cybereason"                      = 25
    "Cisco Secure Endpoint"           = 25
    "Fortinet FortiEDR"               = 25
    "Kaspersky EDR"                   = 25

    # Telemetry / Monitoring Platforms
    "Tanium Endpoint Agent"           = 15
}

$script:edrIndicators = @(

    # =============================================================
    # Microsoft Defender Antivirus
    # =============================================================
    [pscustomobject]@{
        Friendly = "Microsoft Defender Antivirus"
        Proc     = @("msmpeng")
        Svc      = @("windefend")
        Driver   = @("wdfilter", "wdnisdrv")

        Install  = @(
            "C:\ProgramData\Microsoft\Windows Defender",
            "C:\Program Files\Windows Defender"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Defender"
        )
    }

    # =============================================================
    # Microsoft Defender for Endpoint
    # =============================================================
    [pscustomobject]@{
        Friendly = "Microsoft Defender for Endpoint"
        Proc     = @("sense")
        Svc      = @("sense")
        Driver   = @("sense")

        Install  = @(
            "C:\Program Files\Windows Defender Advanced Threat Protection"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
        )
    }

    # =============================================================
    # CrowdStrike Falcon
    # =============================================================
    [pscustomobject]@{
        Friendly = "CrowdStrike Falcon"
        Proc     = @("csfalconservice", "csagent")
        Svc      = @("csfalconservice")
        Driver   = @("csagent")

        Install  = @(
            "C:\Program Files\CrowdStrike"
        )

        Reg      = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent"
        )
    }

    # =============================================================
    # SentinelOne
    # =============================================================
    [pscustomobject]@{
        Friendly = "SentinelOne"
        Proc     = @("sentinelagent")
        Svc      = @("sentinelagent")
        Driver   = @("sentinel")

        Install  = @(
            "C:\Program Files\SentinelOne"
        )

        Reg      = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\SentinelAgent"
        )
    }

    # =============================================================
    # Palo Alto Cortex XDR
    # =============================================================
    [pscustomobject]@{
        Friendly = "Palo Alto Cortex XDR"
        Proc     = @("cyserver")
        Svc      = @("cyserver")
        Driver   = @("cyverak")

        Install  = @(
            "C:\Program Files\Palo Alto Networks"
        )

        Reg      = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\CyveraService"
        )
    }

    # =============================================================
    # Sophos Intercept X
    # =============================================================
    [pscustomobject]@{
        Friendly = "Sophos Intercept X"
        Proc     = @("sophoshealth")
        Svc      = @("sophoshealthservice")
        Driver   = @("sophosflt")

        Install  = @(
            "C:\Program Files\Sophos"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Sophos"
        )
    }

    # =============================================================
    # VMware Carbon Black
    # =============================================================
    [pscustomobject]@{
        Friendly = "VMware Carbon Black"
        Proc     = @("cb")
        Svc      = @("carbonblack")
        Driver   = @("cbk7", "carbonblack")

        Install  = @(
            "C:\Program Files\CarbonBlack"
        )

        Reg      = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\CarbonBlack"
        )
    }

    # =============================================================
    # Trellix / McAfee Enterprise
    # =============================================================
    [pscustomobject]@{
        Friendly = "Trellix Endpoint Security"
        Proc     = @("mfemms", "mcshield")
        Svc      = @("mfemms")
        Driver   = @("mfehidk", "mfewfpk")

        Install  = @(
            "C:\Program Files\McAfee",
            "C:\Program Files\Trellix"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\McAfee",
            "HKLM:\SOFTWARE\Trellix"
        )
    }

    # =============================================================
    # Trend Micro Apex One
    # =============================================================
    [pscustomobject]@{
        Friendly = "Trend Micro Apex One"
        Proc     = @("ntrtscan")
        Svc      = @("tmlisten")
        Driver   = @("tmcomm")

        Install  = @(
            "C:\Program Files\Trend Micro"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\TrendMicro"
        )
    }

    # =============================================================
    # Bitdefender GravityZone
    # =============================================================
    [pscustomobject]@{
        Friendly = "Bitdefender GravityZone"
        Proc     = @("bdservicehost")
        Svc      = @("epsecurityservice")
        Driver   = @("bdvedisk")

        Install  = @(
            "C:\Program Files\Bitdefender"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Bitdefender"
        )
    }

    # =============================================================
    # Elastic Endpoint
    # =============================================================
    [pscustomobject]@{
        Friendly = "Elastic Endpoint Security"
        Proc     = @("elastic-endpoint")
        Svc      = @("elastic-endpoint")
        Driver   = @("elasticendpoint")

        Install  = @(
            "C:\Program Files\Elastic"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Elastic"
        )
    }

    # =============================================================
    # Cybereason
    # =============================================================
    [pscustomobject]@{
        Friendly = "Cybereason"
        Proc     = @("crsservice")
        Svc      = @("cybereason")
        Driver   = @("crsentinel")

        Install  = @(
            "C:\Program Files\Cybereason"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Cybereason"
        )
    }

    # =============================================================
    # Cisco Secure Endpoint
    # =============================================================
    [pscustomobject]@{
        Friendly = "Cisco Secure Endpoint"
        Proc     = @("ciscoamp")
        Svc      = @("ciscoamp")
        Driver   = @()

        Install  = @(
            "C:\Program Files\Cisco\AMP"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Cisco\AMP"
        )
    }

    # =============================================================
    # Fortinet FortiEDR
    # =============================================================
    [pscustomobject]@{
        Friendly = "Fortinet FortiEDR"
        Proc     = @("fortiedr")
        Svc      = @("fortiedr")
        Driver   = @("fortiedr")

        Install  = @(
            "C:\Program Files\Fortinet"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Fortinet"
        )
    }

    # =============================================================
    # Kaspersky
    # =============================================================
    [pscustomobject]@{
        Friendly = "Kaspersky EDR"
        Proc     = @("avp")
        Svc      = @("avp")
        Driver   = @("klif")

        Install  = @(
            "C:\Program Files\Kaspersky Lab"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\KasperskyLab"
        )
    }

    # =============================================================
    # Tanium
    # =============================================================
    [pscustomobject]@{
        Friendly = "Tanium Endpoint Agent"
        Proc     = @("taniumclient")
        Svc      = @("taniumclient")
        Driver   = @()

        Install  = @(
            "C:\Program Files\Tanium\Tanium Client",
            "C:\Program Files (x86)\Tanium\Tanium Client"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\Tanium"
        )
    }

    # =============================================================
    # Check Point Harmony Endpoint
    # =============================================================
    [pscustomobject]@{
        Friendly = "Check Point Harmony Endpoint"
        Proc     = @("epconsole")
        Svc      = @("trac")
        Driver   = @("trufos")

        Install  = @(
            "C:\Program Files\CheckPoint"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\CheckPoint"
        )
    }

    # =============================================================
    # ESET Protect
    # =============================================================
    [pscustomobject]@{
        Friendly = "ESET Protect"
        Proc     = @("ekrn")
        Svc      = @("ekrn")
        Driver   = @("ehdrv")

        Install  = @(
            "C:\Program Files\ESET"
        )

        Reg      = @(
            "HKLM:\SOFTWARE\ESET"
        )
    }

)

function fncGetLoadedDriversLower {

    $drivers = @()

    try {

        $drv = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue

        foreach ($d in $drv) {

            if ((fncSafeString $d.State) -eq "Running") {

                $drivers += fncSafeString $d.Name
            }
        }

    }
    catch {}

    return fncToLowerSet $drivers
}

function fncDetectSecurityDrivers {

    $loaded = fncGetLoadedDriversLower
    $hits = @()

    foreach ($edr in $script:edrIndicators) {

        foreach ($drv in (fncSafeArray $edr.Driver)) {

            if (fncAnyContains $loaded @($drv)) {
                $hits += $drv
            }
        }
    }

    return @($hits | Sort-Object -Unique)
}

function fncScoreEDRProduct {

    param(
        $indicator,
        $procs,
        $svcs,
        $drivers
    )

    $score = 0
    $evidence = @()

    # ---------- Process ----------
    foreach ($p in (fncSafeArray $indicator.Proc)) {

        if (fncAnyContains $procs @($p)) {
            $score += 15
            $evidence += "Process:$p"
        }
    }

    # ---------- Service ----------
    foreach ($s in (fncSafeArray $indicator.Svc)) {

        if (fncAnyContains $svcs @($s)) {
            $score += 25
            $evidence += "Service:$s"
        }
    }

    # ---------- Driver ----------
    foreach ($d in (fncSafeArray $indicator.Driver)) {

        if (fncAnyContains $drivers @($d)) {
            $score += 40
            $evidence += "Driver:$d"
        }
    }

    # ---------- Install Folder ----------
    foreach ($path in (fncSafeArray $indicator.Install)) {

        try {
            if (Test-Path $path) {
                $score += 35
                $evidence += "Install:$path"
            }
        }
        catch {}
    }

    # ---------- Registry ----------
    foreach ($reg in (fncSafeArray $indicator.Reg)) {

        try {
            if (Test-Path $reg) {
                $score += 30
                $evidence += "Registry:$reg"
            }
        }
        catch {}
    }

    return [pscustomobject]@{
        Product  = $indicator.Friendly
        Score    = $score
        Evidence = $evidence
    }
}

function fncGetDefenderTamperProtectionState {

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features"
    )

    foreach ($p in $paths) {

        try {
            if (Test-Path $p) {

                $v = Get-ItemProperty $p -Name TamperProtection -ErrorAction SilentlyContinue

                if ($v) {
                    if ($v.TamperProtection -eq 5 -or $v.TamperProtection -eq 1) {
                        return "Enabled"
                    }

                    if ($v.TamperProtection -eq 0) {
                        return "Disabled"
                    }
                }
            }
        }
        catch {}
    }

    return "Unknown"
}

function fncGetMDESensorHealth {

    if (-not $script:OperatorIsWindows) { return "NotApplicable" }

    $svc = Get-Service Sense -ErrorAction SilentlyContinue
    $onboard = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"

    if ($svc) {
        if ($svc.Status -eq "Running" -and $onboard) {
            return "Healthy"
        }
        elseif ($svc.Status -eq "Running") {
            return "Running_NotOnboarded"
        }
        else {
            return "Installed_NotRunning"
        }
    }

    return "NotDetected"
}

function fncDetectEDR {

    $results = @()

    $procs = fncToLowerSet (Get-Process -ErrorAction SilentlyContinue | Select-Object -Expand ProcessName)
    $svcs = if ($script:OperatorIsWindows) {
        fncToLowerSet (Get-Service -ErrorAction SilentlyContinue | Select-Object -Expand Name)
    }
    else { @() }
    $drivers = if ($script:OperatorIsWindows) { fncDetectSecurityDrivers } else { @() }

    foreach ($ind in $script:edrIndicators) {

        $r = fncScoreEDRProduct $ind $procs $svcs $drivers

        if ($r.Score -ge 10) {

            $evCount = (fncSafeArray $r.Evidence).Count

            if ($evCount -le 1) {
                $confidence = "Low"
            }
            elseif ($r.Score -ge 80) {
                $confidence = "Confirmed"
            }
            elseif ($r.Score -ge 50) {
                $confidence = "Likely"
            }
            else {
                $confidence = "Suspicious"
            }

            $results += [pscustomobject]@{
                Product    = $r.Product
                Score      = $r.Score
                Confidence = $confidence
                Evidence   = $r.Evidence
            }
        }
    }

    return $results
}

function fncDetectSysmon {

    if (-not $script:OperatorIsWindows) { return $false }

    try {
        $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if ($svc) { return $true }
    }
    catch {}

    return $false
}

function fncDetectCredentialGuard {

    try {

        $cg = Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue

        if ($cg.SecurityServicesRunning -contains 1) {
            return "Enabled"
        }

    }
    catch {}

    return "Disabled"
}

function fncDetectWDAC {

    try {

        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue

        if ($ci.CodeIntegrityPolicyEnforcementStatus -eq 2) {
            return "Enforced"
        }

        if ($ci.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            return "Audit"
        }

    }
    catch {}

    return "Disabled"
}

function fncDetectExploitGuard {

    if (-not (fncCommandExists "Get-MpPreference")) {
        return [pscustomobject]@{
            ASR               = "Unknown"
            NetworkProtection = "Unknown"
            ControlledFolder  = "Unknown"
        }
    }

    try {

        $pref = Get-MpPreference

        return [pscustomobject]@{

            ASR               = if ($pref.AttackSurfaceReductionRules_Ids.Count -gt 0) {
                "Configured"
            }
            else {
                "NotConfigured"
            }

            NetworkProtection = if ($pref.EnableNetworkProtection -eq 1) {
                "Enabled"
            }
            else {
                "Disabled"
            }

            ControlledFolder  = if ($pref.EnableControlledFolderAccess -eq 1) {
                "Enabled"
            }
            else {
                "Disabled"
            }
        }

    }
    catch {

        return [pscustomobject]@{
            ASR               = "Unknown"
            NetworkProtection = "Unknown"
            ControlledFolder  = "Unknown"
        }
    }
}

function fncComputeEDRWeightScore {
    param($products)

    $sum = 0

    foreach ($p in (fncSafeArray $products)) {
        if ($script:edrWeights.ContainsKey($p)) {
            $sum += $script:edrWeights[$p]
        }
        else {
            $sum += 25
        }
    }

    if ($sum -gt 70) { $sum = 70 }

    return $sum
}

# ================================================================
# Linux / macOS detection helpers
# ================================================================

function fncDetectLinuxSecurityTools {

    $procs = fncToLowerSet (Get-Process -ErrorAction SilentlyContinue | Select-Object -Expand ProcessName)
    $found = [System.Collections.Generic.List[pscustomobject]]::new()
    $seenProducts = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $script:linuxSecurityProcs.Keys) {

        $product = $script:linuxSecurityProcs[$key]

        if (($procs -contains $key) -and ($product -notin $seenProducts)) {
            $seenProducts.Add($product)
            $found.Add([pscustomobject]@{
                    Product    = $product
                    Score      = 20
                    Confidence = "Confirmed"
                    Evidence   = @("process:$key")
                })
        }
    }

    return $found.ToArray()
}

function fncDetectLinuxAppArmor {

    try {
        if (Test-Path "/sys/kernel/security/apparmor") { return "Active" }
    }
    catch {}

    try {
        $mod = (& bash -c "lsmod 2>/dev/null | grep -q apparmor && echo Present || echo Absent").Trim()
        if ($mod -eq "Present") { return "Active" }
    }
    catch {}

    return "NotInstalled"
}

function fncDetectLinuxSELinux {

    try {
        $se = (& bash -c "getenforce 2>/dev/null").Trim()
        if ($se) { return $se }
    }
    catch {}

    return "NotInstalled"
}

function fncDetectLinuxFirewall {

    try {
        $ufw = (& bash -c "ufw status 2>/dev/null | head -1").Trim()
        if ($ufw -match "active") { return "Active (ufw)" }
        if ($ufw -match "inactive") { return "Inactive (ufw)" }
    }
    catch {}

    try {
        $fw = (& bash -c "firewall-cmd --state 2>/dev/null").Trim()
        if ($fw -eq "running") { return "Active (firewalld)" }
    }
    catch {}

    try {
        $ipt = (& bash -c "iptables -L 2>/dev/null | grep -cv 'Chain\|target\|^$'").Trim()
        if ([int]$ipt -gt 0) { return "Active (iptables)" }
    }
    catch {}

    return "NotDetected"
}

function fncDetectLinuxAuditd {

    try {
        $st = (& bash -c "systemctl is-active auditd 2>/dev/null").Trim()
        if ($st -eq "active") { return "Running" }
        if ($st) { return "Stopped" }
    }
    catch {}

    try {
        $procID = (& bash -c "pgrep -x auditd 2>/dev/null").Trim()
        if ($procID) { return "Running" }
    }
    catch {}

    return "NotInstalled"
}

function fncDetectLinuxASLR {

    try {
        $val = (& bash -c "sysctl -n kernel.randomize_va_space 2>/dev/null").Trim()
        switch ($val) {
            "2" { return "Full" }
            "1" { return "Partial" }
            "0" { return "Disabled" }
        }
    }
    catch {}

    return "Unknown"
}

function fncCollectLinuxTelemetry {

    $currentOS = "Linux"
    try {
        if (Get-Variable IsMacOS -ErrorAction SilentlyContinue) {
            if ($IsMacOS) { $currentOS = "macOS" }
        }
    }
    catch {}

    $edrResults = @(fncDetectLinuxSecurityTools)
    $products = @($edrResults | ForEach-Object { $_.Product } | Sort-Object -Unique)

    $isRoot = $false
    try {
        $uid = (& bash -c "id -u 2>/dev/null").Trim()
        $isRoot = ($uid -eq "0")
    }
    catch {}

    $isLinuxOS = ($currentOS -eq "Linux")

    $tele = [pscustomobject]@{
        SchemaVersion     = 4
        Timestamp         = Get-Date
        OS                = $currentOS

        SecurityDrivers   = @()
        EDRFindings       = $edrResults
        Products          = $products

        AppArmor          = if ($isLinuxOS) { fncDetectLinuxAppArmor }  else { "NotApplicable" }
        SELinux           = if ($isLinuxOS) { fncDetectLinuxSELinux }   else { "NotApplicable" }
        Firewall          = fncDetectLinuxFirewall
        Auditd            = if ($isLinuxOS) { fncDetectLinuxAuditd }    else { "NotApplicable" }
        ASLR              = if ($isLinuxOS) { fncDetectLinuxASLR }      else { "Unknown" }
        RunningAsRoot     = $isRoot

        # Windows compat fields - not applicable on Linux/macOS
        Tamper            = "N/A"
        MDE               = "NotApplicable"
        Sysmon            = $false
        CredentialGuard   = "N/A"
        WDAC              = "N/A"
        ASR               = "N/A"
        NetworkProtection = "N/A"
        ControlledFolder  = "N/A"
    }

    $global:ProberState.OperatorTelemetry = $tele

    try {
        $path = fncGetTelemetryCachePath
        $tmp = "$path.tmp"
        $tele | ConvertTo-Json -Depth 6 | Set-Content $tmp
        [System.IO.File]::Replace($tmp, $path, $null)
    }
    catch {}

    return $tele
}

function fncScoreLinuxRisk {

    param($tele)

    $score = 0

    # Security tools lower attacker risk (higher score = harder target)
    $products = fncSafeArray $tele.Products
    $toolScore = [Math]::Min(($products.Count * 10), 30)
    $score += $toolScore

    $fw = fncSafeString $tele.Firewall
    if ($fw -like "*Active*") { $score += 20 }

    $auditd = fncSafeString $tele.Auditd
    if ($auditd -eq "Running") { $score += 15 }

    $aa = fncSafeString $tele.AppArmor
    $se = fncSafeString $tele.SELinux
    if ($aa -eq "Active" -or $se -eq "Enforcing") { $score += 20 }

    $aslr = fncSafeString $tele.ASLR
    if ($aslr -eq "Full") { $score += 15 }
    elseif ($aslr -eq "Partial") { $score += 8 }

    if ($score -gt 100) { $score = 100 }

    return [pscustomobject]@{
        Score    = $score
        Level    = fncScoreToLevel $score
        Products = $tele.Products
    }
}

# ================================================================
# Telemetry collector (branched by OS)
# ================================================================

function fncCollectOperatorTelemetry {

    if (-not $script:OperatorIsWindows) {
        return fncCollectLinuxTelemetry
    }

    $eg = fncDetectExploitGuard
    $edrResults = @(fncDetectEDR)

    $products = @()

    foreach ($r in $edrResults) {

        if ($null -ne $r.Product) {
            $products += $r.Product
        }
    }

    $products = @($products | Sort-Object -Unique)

    $tele = [pscustomobject]@{

        SchemaVersion     = 4
        Timestamp         = Get-Date

        # Core Security Detection
        SecurityDrivers   = @(fncDetectSecurityDrivers)

        EDRFindings       = $edrResults
        Products          = $products

        # Defender / Platform
        Tamper            = fncGetDefenderTamperProtectionState
        MDE               = fncGetMDESensorHealth

        # Host Controls
        Sysmon            = fncDetectSysmon
        CredentialGuard   = fncDetectCredentialGuard
        WDAC              = fncDetectWDAC

        # Exploit Guard
        ASR               = $eg.ASR
        NetworkProtection = $eg.NetworkProtection
        ControlledFolder  = $eg.ControlledFolder
    }

    $global:ProberState.OperatorTelemetry = $tele

    try {

        $path = fncGetTelemetryCachePath
        $tmp = "$path.tmp"

        $tele | ConvertTo-Json -Depth 6 | Set-Content $tmp
        [System.IO.File]::Replace($tmp, $path, $null)

    }
    catch {}

    return $tele
}

function fncGetOperatorTelemetry {

    if ($global:ProberState.OperatorTelemetry) {

        $t = $global:ProberState.OperatorTelemetry
        $need = @(
            "SchemaVersion",
            "Products",
            "EDRFindings",
            "Tamper",
            "MDE",
            "Sysmon",
            "CredentialGuard",
            "WDAC",
            "ASR",
            "NetworkProtection",
            "ControlledFolder",
            "SecurityDrivers"
        )


        foreach ($k in $need) {
            if ($t.PSObject.Properties.Name -notcontains $k) {
                return fncCollectOperatorTelemetry
            }
        }

        if ([int]$t.SchemaVersion -lt 4) {
            return fncCollectOperatorTelemetry
        }

        return $t
    }

    try {
        $path = fncGetTelemetryCachePath

        if (Test-Path $path) {

            $data = Get-Content $path -Raw | ConvertFrom-Json

            # ----- SCHEMA VALIDATION -----
            if (
                $null -eq $data.SchemaVersion -or
                [int]$data.SchemaVersion -lt 2 -or
                $null -eq $data.SecurityDrivers -or
                $null -eq $data.Products -or
                $null -eq $data.Tamper -or
                $null -eq $data.Sysmon -or
                $null -eq $data.WDAC -or
                $null -eq $data.ASR -or
                $null -eq $data.EDRFindings
            ) {
                return fncCollectOperatorTelemetry
            }

            $global:ProberState.OperatorTelemetry = $data
            return $data
        }

    }
    catch {}

    return fncCollectOperatorTelemetry
}

function fncScoreEDREvasionAwareness {

    $tele = fncGetOperatorTelemetry

    if ($tele.PSObject.Properties.Name -contains "OS" -and
        $tele.OS -ne "Windows" -and
        $null -ne $tele.OS) {
        return fncScoreLinuxRisk $tele
    }

    $products = fncSafeArray $tele.Products
    $weight = fncComputeEDRWeightScore $products

    $score = $weight

    if ((fncSafeString $tele.Tamper) -eq "Enabled") { $score += 10 }
    if ($tele.MDE -eq "Healthy") { $score += 10 }
    if ($tele.Sysmon) { $score += 10 }
    if ($tele.CredentialGuard -eq "Enabled") { $score += 15 }
    if ($tele.WDAC -eq "Enforced") { $score += 15 }
    if ($tele.ASR -eq "Configured") { $score += 10 }
    if ($tele.NetworkProtection -eq "Enabled") { $score += 5 }
    if ($tele.ControlledFolder -eq "Enabled") { $score += 5 }

    if ($score -gt 100) { $score = 100 }

    if ((fncSafeCount $tele.SecurityDrivers) -gt 0) {
        $score += 5
    }

    return [pscustomobject]@{
        Score    = $score
        Level    = fncScoreToLevel $score
        Products = $tele.Products
    }
}

function fncScoreToLevel {
    param([int]$Score)

    if ($Score -ge 70) { return "RED" }
    if ($Score -ge 40) { return "AMBER" }
    return "GREEN"
}

function fncPrintLinuxRiskBanner {

    param($risk, $tele)

    function fncGetTeleValLinux {
        param([string]$Name, $Default = $null)
        try {
            if ($null -eq $tele) { return $Default }
            if ($tele.PSObject.Properties.Name -notcontains $Name) { return $Default }
            $v = $tele.$Name
            if ($null -eq $v) { return $Default }
            return $v
        }
        catch { return $Default }
    }

    function fncColourLineLinux {
        param([string]$Name, [string]$Value, [bool]$IsGood)
        fncWriteColour ("  {0,-22}: " -f $Name) White -NoNewLine
        if ($IsGood) { fncWriteColour $Value Green }
        else { fncWriteColour $Value Red }
    }

    Write-Host ""
    fncWriteColour "{~} OPERATOR RISK" Cyan
    Write-Host ""

    # ── Score + level bar on one line ────────────────────────────
    fncWriteColour "  Score  : " White -NoNewLine
    fncWriteColour ("{0}/100" -f $risk.Score) Cyan -NoNewLine
    fncWriteColour "   " White -NoNewLine
    foreach ($lvl in @("GREEN", "AMBER", "RED")) {
        $lvlCol = if ($lvl -eq $risk.Level) { fncOperatorRiskColour $lvl } else { [System.ConsoleColor]::DarkGray }
        fncWriteColour ("[{0}]" -f $lvl) $lvlCol -NoNewLine
        fncWriteColour "  " White -NoNewLine
    }
    Write-Host ""
    Write-Host ""

    $linuxEvidence = fncGetTeleValLinux "EDRFindings" @()
    if ((fncSafeCount $linuxEvidence) -gt 0) {
        fncWriteColour "Security Stack" Cyan
        fncWriteColour "--------------" DarkGray
        foreach ($ev in (fncSafeArray $linuxEvidence)) {
            $conf    = fncSafeString $ev.Confidence
            $nameCol = switch ($conf) {
                "Confirmed"  { "Red"        }
                "Likely"     { "Yellow"     }
                "Suspicious" { "DarkYellow" }
                default      { "DarkGray"   }
            }
            $matched = (fncSafeArray $ev.Evidence).Count
            $sigStr  = "{0} {1}" -f $matched, (if ($matched -eq 1) { "signal" } else { "signals" })
            fncWriteColour ("  {0,-40}" -f $ev.Product) $nameCol -NoNewLine
            fncWriteColour ("{0,-14}" -f $conf) $nameCol -NoNewLine
            fncWriteColour $sigStr DarkGray
        }
        Write-Host ""
    }

    fncWriteColour "Security Controls" Cyan
    fncWriteColour "-----------------" DarkGray

    $fw = fncSafeString (fncGetTeleValLinux "Firewall" "Unknown")
    fncColourLineLinux "Firewall" $fw ($fw -like "*Active*")

    $auditd = fncSafeString (fncGetTeleValLinux "Auditd" "Unknown")
    fncColourLineLinux "Audit Daemon" $auditd ($auditd -eq "Running")

    $aa = fncSafeString (fncGetTeleValLinux "AppArmor" "Unknown")
    if ($aa -ne "NotApplicable") {
        fncColourLineLinux "AppArmor" $aa ($aa -eq "Active")
    }

    $se = fncSafeString (fncGetTeleValLinux "SELinux" "Unknown")
    if ($se -ne "NotApplicable") {
        fncColourLineLinux "SELinux" $se ($se -eq "Enforcing")
    }

    $aslr = fncSafeString (fncGetTeleValLinux "ASLR" "Unknown")
    fncColourLineLinux "ASLR" $aslr ($aslr -eq "Full" -or $aslr -eq "Partial")

    $root = [bool](fncGetTeleValLinux "RunningAsRoot" $false)
    fncWriteColour ("  {0,-22}: " -f "Running as Root") White -NoNewLine
    if ($root) { fncWriteColour "Yes" Red }
    else { fncWriteColour "No"  Green }

    Write-Host ""
    Write-Host ""
}

function fncPrintOperatorRiskBanner {

    $risk = fncScoreEDREvasionAwareness
    $tele = fncGetOperatorTelemetry

    if ($tele.PSObject.Properties.Name -contains "OS" -and
        $tele.OS -ne "Windows" -and
        $null -ne $tele.OS) {
        fncPrintLinuxRiskBanner $risk $tele
        return
    }

    function fncGetTeleVal {
        param(
            [Parameter(Mandatory = $true)][string]$Name,
            $Default = $null
        )

        try {
            if ($null -eq $tele) { return $Default }
            if ($tele.PSObject.Properties.Name -notcontains $Name) { return $Default }

            $v = $tele.$Name
            if ($null -eq $v) { return $Default }

            return $v
        }
        catch {
            return $Default
        }
    }

    Write-Host ""

    # =========================================================
    # Risk Header
    # =========================================================

    fncWriteColour "{~} OPERATOR RISK" Cyan
    Write-Host ""

    # ── Score + level bar on one line ────────────────────────────
    fncWriteColour "  Score  : " White -NoNewLine
    fncWriteColour ("{0}/100" -f $risk.Score) Cyan -NoNewLine
    fncWriteColour "   " White -NoNewLine
    foreach ($lvl in @("GREEN", "AMBER", "RED")) {
        $lvlCol = if ($lvl -eq $risk.Level) { fncOperatorRiskColour $lvl } else { [System.ConsoleColor]::DarkGray }
        fncWriteColour ("[{0}]" -f $lvl) $lvlCol -NoNewLine
        fncWriteColour "  " White -NoNewLine
    }
    Write-Host ""
    Write-Host ""

    $evidence = fncGetTeleVal "EDRFindings" @()

    # =========================================================
    # Security Products (condensed)
    # =========================================================

    if ((fncSafeCount $evidence) -gt 0) {

        fncWriteColour "Security Stack" Cyan
        fncWriteColour "--------------" DarkGray

        foreach ($ev in (fncSafeArray $evidence)) {

            $conf    = fncSafeString $ev.Confidence
            $nameCol = switch ($conf) {
                "Confirmed"  { "Red"        }
                "Likely"     { "Yellow"     }
                "Suspicious" { "DarkYellow" }
                default      { "DarkGray"   }
            }

            $matched = (fncSafeArray $ev.Evidence).Count

            $total = 0
            $ind = $script:edrIndicators | Where-Object { $_.Friendly -eq $ev.Product } | Select-Object -First 1
            if ($ind) {
                $total = (fncSafeArray $ind.Proc).Count    +
                         (fncSafeArray $ind.Svc).Count     +
                         (fncSafeArray $ind.Driver).Count  +
                         (fncSafeArray $ind.Install).Count +
                         (fncSafeArray $ind.Reg).Count
            }

            $sigStr = if ($total -gt 0) { "{0}/{1} signals" -f $matched, $total } else { "{0} signals" -f $matched }

            fncWriteColour ("  {0,-40}" -f $ev.Product) $nameCol -NoNewLine
            fncWriteColour ("{0,-14}" -f $conf) $nameCol -NoNewLine
            fncWriteColour $sigStr DarkGray
        }

        Write-Host ""
    }

    # =========================================================
    # Kernel Drivers  (red team only)
    # =========================================================

    $isBlue = (fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")) -eq "blue"

    if (-not $isBlue) {

        $drivers = fncGetTeleVal "SecurityDrivers" @()

        if ((fncSafeCount $drivers) -gt 0) {

            fncWriteColour "Kernel Drivers" Cyan
            fncWriteColour "--------------" DarkGray

            fncWriteColour ("  {0}" -f ($drivers -join ", ")) Red

            Write-Host ""
        }
    }

    # =========================================================
    # Security Controls
    # =========================================================

    fncWriteColour "Security Controls" Cyan
    fncWriteColour "-----------------" DarkGray

    function fncColourLine {

        param(
            [string]$Name,
            [string]$Value,
            [bool]$IsRisk
        )

        fncWriteColour ("  {0,-22}: " -f $Name) White -NoNewLine

        if ($IsRisk) {
            fncWriteColour $Value Red
        }
        else {
            fncWriteColour $Value Green
        }
    }

    $sysmon = [bool](fncGetTeleVal "Sysmon" $false)
    fncColourLine "Sysmon" ($(if ($sysmon) { "Present" } else { "NotDetected" })) $sysmon

    $wdac = [string](fncGetTeleVal "WDAC" "Unknown")
    fncColourLine "WDAC" $wdac ($wdac -eq "Enforced")

    $cg = [string](fncGetTeleVal "CredentialGuard" "Unknown")
    fncColourLine "Credential Guard" $cg ($cg -eq "Enabled")

    $asr = [string](fncGetTeleVal "ASR" "Unknown")
    fncColourLine "ASR Rules" $asr ($asr -eq "Configured")

    $np = [string](fncGetTeleVal "NetworkProtection" "Unknown")
    fncColourLine "Network Protection" $np ($np -eq "Enabled")

    $cfa = [string](fncGetTeleVal "ControlledFolder" "Unknown")
    fncColourLine "Controlled Folder" $cfa ($cfa -eq "Enabled")

    $tamper = [string](fncGetTeleVal "Tamper" "Unknown")
    fncColourLine "Tamper Protection" $tamper ($tamper -eq "Enabled")

    $mde = [string](fncGetTeleVal "MDE" "Unknown")
    fncColourLine "MDE Sensor" $mde ($mde -eq "Healthy")

    Write-Host ""
}

Export-ModuleMember -Function @(
    "fncPrintOperatorRiskBanner",
    "fncCollectOperatorTelemetry",
    "fncGetOperatorTelemetry"
)
