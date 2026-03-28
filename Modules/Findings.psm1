# ================================================================
# Module  : Findings.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ensure findings store is a hashtable
if (-not $global:ProberState) {
    throw "ProberState is not initialised."
}

if (-not ($global:ProberState.Findings -is [hashtable])) {

    $newStore = @{}

    foreach ($f in @($global:ProberState.Findings)) {

        if ($null -eq $f) { continue }

        $hostName = ""
        if ($f.PSObject.Properties.Name -contains "Host" -and $f.Host) {
            $hostName = [string]$f.Host
        }
        elseif ($global:ProberState.RunContext -and $global:ProberState.RunContext.Host) {
            $hostName = [string]$global:ProberState.RunContext.Host
        }
        else {
            $hostName = try { [System.Net.Dns]::GetHostName() } catch { if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { "unknown" } }
        }

        $key = "{0}:{1}" -f ([string]$f.Id), $hostName
        $newStore[$key] = $f
    }

    $global:ProberState.Findings = $newStore
}

function fncShortHashTag {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Input
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($Input)
    $hash = $sha.ComputeHash($bytes)
    $hex = [BitConverter]::ToString($hash).Replace("-", "")
    return $hex.Substring(0, 5)
}

# ================================================================
# Function: fncNewFinding
# Purpose : Create standardized finding object
# ================================================================
function fncNewFinding {

    param(
        [string]$Id,
        [string]$Title,
        [string]$Category,
        [string]$Severity,
        [string]$HostName,
        [string]$Status,
        [string]$Message,
        [string]$Recommendation,
        [string[]]$Evidence,
        [string[]]$SourceTests,
        [string]$Exploitation,
        [string]$Remediation,
        $TestMeta,
        $Mitre,
        $CWE,
        $NIST,
        $CIS
    )

    return [pscustomobject]@{
        Id             = $Id
        Title          = $Title
        Category       = $Category
        Severity       = $Severity
        Host           = $HostName
        Status         = $Status
        Message        = $Message
        Recommendation = $Recommendation
        Evidence       = @($Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        SourceTests    = @($SourceTests | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        Exploitation   = $Exploitation
        Remediation    = $Remediation
        TestMeta       = $TestMeta
        Mitre          = @($Mitre)
        CWE            = @($CWE)
        NIST           = @($NIST)
        CIS            = @($CIS)
        Timestamp      = Get-Date
        FirstSeen      = Get-Date
        LastSeen       = Get-Date
    }
}

# ================================================================
# Function: fncSubmitFinding
# Purpose : Centralized finding submission and deduplication
# ================================================================
function fncSubmitFinding {

    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [string]$Category = "Uncategorised",

        [ValidateSet("Info", "Low", "Medium", "High", "Critical")]
        [string]$Severity = "Info",

        [string]$HostName = "",
        [string]$Status = "",
        [string]$Message = "",
        [string]$Recommendation = "",
        [string[]]$Evidence = @(),
        [string[]]$SourceTests = @(),
        [string]$Exploitation = "",
        [string]$Remediation = "",
        $TestMeta = $null,
        $Mitre = @(),
        $CWE = @(),
        $NIST = @(),
        $CIS = @()
    )

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        if ($global:ProberState.RunContext -and $global:ProberState.RunContext.Host) {
            $HostName = [string]$global:ProberState.RunContext.Host
        }
        else {
            $HostName = try { [System.Net.Dns]::GetHostName() } catch { if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { "unknown" } }
        }
    }

    # Auto-inject mappings from the test registry when none are explicitly supplied
    if (($Mitre.Count -eq 0) -and ($CWE.Count -eq 0) -and ($NIST.Count -eq 0) -and
        (fncSafeCount $SourceTests) -gt 0) {

        $testId = fncSafeString $SourceTests[0]
        $testObj = @(fncSafeArray $global:ProberState.Tests |
            Where-Object { (fncSafeString $_.Id) -eq $testId }) | Select-Object -First 1

        if ($testObj -and $testObj.Mappings) {
            $m = $testObj.Mappings
            if ($m.PSObject.Properties.Name -contains "MitreAttack" -and $m.MitreAttack) { $Mitre = @($m.MitreAttack) }
            if ($m.PSObject.Properties.Name -contains "CWE" -and $m.CWE) { $CWE = @($m.CWE) }
            if ($m.PSObject.Properties.Name -contains "Nist" -and $m.Nist) { $NIST = @($m.Nist) }
            if ($m.PSObject.Properties.Name -contains "CIS" -and $m.CIS) { $CIS = @($m.CIS) }
        }
    }

    $key = "$Id`:$HostName"

    if ($global:ProberState.Findings.ContainsKey($key)) {

        $existing = $global:ProberState.Findings[$key]

        foreach ($ev in @($Evidence)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$ev) -and ($existing.Evidence -notcontains $ev)) {
                $existing.Evidence += $ev
            }
        }

        foreach ($src in @($SourceTests)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$src) -and ($existing.SourceTests -notcontains $src)) {
                $existing.SourceTests += $src
            }
        }

        $existing.LastSeen = Get-Date

        if ([string]::IsNullOrWhiteSpace([string]$existing.Message) -and $Message) {
            $existing.Message = $Message
        }

        if ([string]::IsNullOrWhiteSpace([string]$existing.Recommendation) -and $Recommendation) {
            $existing.Recommendation = $Recommendation
        }

        if ([string]::IsNullOrWhiteSpace([string]$existing.Status) -and $Status) {
            $existing.Status = $Status
        }

        try { fncLog "DEBUG" ("Merged evidence into finding [{0}]" -f $Id) } catch {}
    }
    else {

        $finding = fncNewFinding `
            -Id $Id `
            -Title $Title `
            -Category $Category `
            -Severity $Severity `
            -HostName $HostName `
            -Status $Status `
            -Message $Message `
            -Recommendation $Recommendation `
            -Evidence $Evidence `
            -SourceTests $SourceTests `
            -Exploitation $Exploitation `
            -Remediation $Remediation `
            -TestMeta $TestMeta `
            -Mitre $Mitre `
            -CWE $CWE `
            -NIST $NIST `
            -CIS $CIS

        $global:ProberState.Findings[$key] = $finding

        try { fncLog "DEBUG" ("New finding registered [{0}]" -f $Id) } catch {}
    }
}

function fncGetSeverityRank {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return 6 }
        "High" { return 5 }
        "Medium" { return 4 }
        "Low" { return 3 }
        "Info" { return 2 }
        default { return 0 }
    }
}

function fncGetSeverityColour {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return "DarkRed" }
        "High" { return "Red" }
        "Medium" { return "Yellow" }
        "Low" { return "Cyan" }
        "Info" { return "DarkGray" }
        default { return "White" }
    }
}

function fncGetSeveritySymbol {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return "[-]" }
        "High" { return "[!]" }
        "Medium" { return "[!]" }
        "Low" { return "[i]" }
        "Info" { return "[i]" }
        default { return "[?]" }
    }
}

# ================================================================
# KEV lazy-loader (no network during display - uses cached data only)
# ================================================================
$script:_kevLookup = $null

function fncGetKevLookupCached {

    if ($null -ne $script:_kevLookup) { return $script:_kevLookup }

    $script:_kevLookup = @{}

    try {
        if (fncCommandExists "fncGetKevData") {
            $cacheRoot = Join-Path ([string]$global:ProberState.Runtime.ScriptRoot) "Logs"
            $kev = fncGetKevData -CacheRoot $cacheRoot -NoNetwork
            if ($kev -and $kev.Lookup) {
                $script:_kevLookup = $kev.Lookup
            }
        }
    }
    catch {}

    return $script:_kevLookup
}

function fncPrintFindingsSummary {

    try { fncLog "DEBUG" "Printing findings summary" } catch {}

    $all = fncSafeArray $global:ProberState.Findings.Values

    if ((fncSafeCount $all) -eq 0) {
        try { fncPrintMessage "Findings: none yet." "success" }
        catch { Write-Host "Findings: none yet." }
        try { fncLog "INFO" "Findings summary displayed: none present" } catch {}
        return
    }

    $counts = @{
        Critical = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Critical"))
        High     = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "High"))
        Medium   = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Medium"))
        Low      = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Low"))
        Info     = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Info"))
    }

    try {
        if (fncCommandExists "fncWriteColour") {

            $bannerColour = [System.ConsoleColor]::Green
            if ($counts.Critical -gt 0) { $bannerColour = [System.ConsoleColor]::Red }
            elseif ($counts.High -gt 0) { $bannerColour = [System.ConsoleColor]::DarkRed }
            elseif ($counts.Medium -gt 0) { $bannerColour = [System.ConsoleColor]::Yellow }

            fncWriteColour "[!] Findings => " $bannerColour -NoNewLine

            $cColour = if ($counts.Critical -gt 0) { [System.ConsoleColor]::Red } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Critical:{0} | " -f $counts.Critical) $cColour -NoNewLine

            $hColour = if ($counts.High -gt 0) { [System.ConsoleColor]::DarkRed } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("High:{0} | " -f $counts.High) $hColour -NoNewLine

            $mColour = if ($counts.Medium -gt 0) { [System.ConsoleColor]::Yellow } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Medium:{0} | " -f $counts.Medium) $mColour -NoNewLine

            $lColour = if ($counts.Low -gt 0) { [System.ConsoleColor]::Cyan } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Low:{0} | " -f $counts.Low) $lColour -NoNewLine

            $iColour = if ($counts.Info -gt 0) { [System.ConsoleColor]::White } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Info:{0} |" -f $counts.Info) $iColour
        }
        else {
            Write-Host ("Findings => Critical:{0} | High:{1} | Medium:{2} | Low:{3} | Info:{4} " -f `
                    $counts.Critical, $counts.High, $counts.Medium, $counts.Low, $counts.Info)
        }

        fncLog "INFO" ("Findings summary => C:{0} H:{1} M:{2} L:{3} I:{4}" -f `
                $counts.Critical, $counts.High, $counts.Medium, $counts.Low, $counts.Info)
    }
    catch {
        Write-Host "Findings summary display failed."
    }
}

function fncPrintFindings {
    param(
        [ValidateSet("All", "Critical", "High", "Medium", "Low", "Info")]
        [string]$SeverityFilter = "All"
    )

    $items = fncSafeArray $global:ProberState.Findings.Values
    if ((fncSafeCount $items) -eq 0) { fncPrintMessage "No findings to display." "info"; return }

    if ($SeverityFilter -ne "All") {
        $items = fncSafeArray ($items | Where-Object Severity -eq $SeverityFilter)
    }
    if ((fncSafeCount $items) -eq 0) { fncPrintMessage ("No findings matched filter: {0}" -f $SeverityFilter) "info"; return }

    $items = fncSafeArray (
        $items | Sort-Object @{ Expression = { fncGetSeverityRank $_.Severity }; Descending = $true }, Category, Title
    )

    fncPrintSectionHeader ("FINDINGS ({0})" -f $SeverityFilter.ToUpperInvariant())

    foreach ($f in $items) {
        $severity = fncSafeString $f.Severity
        $colour = fncGetSeverityColour $severity
        $symbol = fncGetSeveritySymbol $severity

        $header = "$symbol [$severity] $($f.Id) | $($f.Category) | $($f.Title)"

        if (fncCommandExists "fncWriteColour") {
            fncWriteColour $header $colour

            if (-not [string]::IsNullOrWhiteSpace([string]$f.Status)) {
                fncWriteColour ("Status: $($f.Status)") White
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$f.Message)) {
                fncWriteColour ("Message: $($f.Message)") White
            }

            if ($f.PSObject.Properties.Name -contains "Exploitation" -and -not [string]::IsNullOrWhiteSpace([string]$f.Exploitation)) {
                fncWriteColour ("Exploitation: $($f.Exploitation)") White
            }

            $rem = ""
            if ($f.PSObject.Properties.Name -contains "Remediation") { $rem = [string]$f.Remediation }
            if ([string]::IsNullOrWhiteSpace($rem)) { $rem = [string]$f.Recommendation }
            if (-not [string]::IsNullOrWhiteSpace($rem)) {
                fncWriteColour ("Remediation: $rem") White
            }

            foreach ($ev in @(fncSafeArray $f.Evidence)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$ev)) {
                    fncWriteColour ("Evidence: $ev") DarkGray
                }
            }

            # NIST control tags
            $nistItems = @(fncSafeArray $f.NIST)
            if ($nistItems.Count -gt 0) {
                $nistIds = @($nistItems | ForEach-Object {
                    $id = ""
                    try { $id = [string]$_.Id } catch {}
                    if (-not $id) { try { $id = [string]$_ } catch {} }
                    $id
                } | Where-Object { $_ })
                if ($nistIds.Count -gt 0) {
                    fncWriteColour ("NIST : " + ($nistIds | ForEach-Object { "[$_]" }) -join " ") DarkGray
                }
            }

            # KEV badge - scan evidence + title for CVE patterns, check local cache only
            try {
                $allText = (@($f.Evidence) + $f.Title + $f.Message) -join " "
                $cveMatches = [regex]::Matches($allText, 'CVE-\d{4}-\d+')
                if ($cveMatches.Count -gt 0) {
                    $kevLookup = fncGetKevLookupCached
                    foreach ($m in $cveMatches) {
                        $cveId = $m.Value.ToUpper()
                        if ($kevLookup -and $kevLookup.ContainsKey($cveId)) {
                            fncWriteColour "[KEV] " Red -NoNewLine
                            fncWriteColour ("{0} is on the CISA Known Exploited Vulnerabilities list" -f $cveId) Yellow
                        }
                    }
                }
            }
            catch {}

            if ((fncSafeCount (fncSafeArray $f.SourceTests)) -gt 0) {
                fncWriteColour ("Detected By: " + (@($f.SourceTests) -join ", ")) DarkGray
            }

            fncWriteColour ("Timestamp: $($f.Timestamp)") DarkGray
        }
        else {
            Write-Host $header
            Write-Host "Status: $($f.Status)"
            Write-Host "Message: $($f.Message)"
        }

        if (fncCommandExists "fncRenderDivider") { fncRenderDivider }
        Write-Host ""
    }
}

Export-ModuleMember -Function @(
    "fncNewFinding",
    "fncSubmitFinding",
    "fncPrintFindingsSummary",
    "fncPrintFindings",
    "fncGetSeverityColour",
    "fncGetSeveritySymbol",
    "fncShortHashTag",
    "fncGetKevLookupCached"
)