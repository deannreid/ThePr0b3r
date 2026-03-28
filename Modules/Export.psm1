# ================================================================
# Module  : Export.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ================================================================
# Internal: console progress helpers
# ================================================================

function fncExportStep { param([string]$Msg) fncPrintMessage ("  >> {0}" -f $Msg) "info" }
function fncExportOk { param([string]$Msg) fncPrintMessage ("  [+] {0}" -f $Msg) "success" }
function fncExportWarn { param([string]$Msg) fncPrintMessage ("  [!] {0}" -f $Msg) "warning" }
function fncExportFail { param([string]$Msg) fncPrintMessage ("  [x] {0}" -f $Msg) "error" }

# Safe string property accessor - returns "" when property does not exist on the object
function fncExportStrProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return "" }
    try {
        if ($Obj.PSObject.Properties.Name -contains $Name) { return [string]$Obj.$Name }
    }
    catch {}
    return ""
}

# ================================================================
# Internal: resolve paths
# ================================================================

function fncExportGetRepoRoot {
    # ProberState.Runtime.ScriptRoot is the repo root when set
    try {
        $r = [string]$global:ProberState.Runtime.ScriptRoot
        if ($r -and (Test-Path $r)) { return $r }
    }
    catch {}

    # PSScriptRoot for this module is ...\Modules\ - go one level up
    if ($PSScriptRoot) {
        $p = Split-Path $PSScriptRoot -Parent
        if (Test-Path $p) { return $p }
    }

    return $PWD.Path
}

function fncExportGetOutputDir {
    # Resolve <repo root>\exports\<hostname>-<runId>\
    # and create it if it does not already exist.

    $root = fncExportGetRepoRoot

    $hostname = ""
    try { $hostname = [System.Net.Dns]::GetHostName() } catch {}
    if (-not $hostname) { $hostname = "unknown" }

    $runId = ""
    try { $runId = [string]$global:ProberState.RunContext.RunId } catch {}
    if (-not $runId) { $runId = [guid]::NewGuid().ToString() }

    $subFolder = ("{0}-{1}" -f $hostname, $runId)
    $dir = Join-Path (Join-Path $root "exports") $subFolder

    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    return $dir
}

function fncExportCheckPath {
    param([string]$Path, [bool]$Force, [string]$Format)

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        fncPrintMessage ("{0} file already exists: {1}" -f $Format, $Path) "warning"
        fncPrintMessage "Use -Force to overwrite." "info"
        return $false
    }

    return $true
}

# ================================================================
# Internal: run context for HTML / JSON
# ================================================================

function fncExportGetRunContext {

    $hostname = "unknown"
    try { $hostname = [System.Net.Dns]::GetHostName() } catch {}

    $user = "unknown"
    try { $user = [Environment]::UserName } catch {
        if ($env:USERNAME) { $user = $env:USERNAME }
        elseif ($env:USER) { $user = $env:USER }
    }

    $ip = "Unknown"
    try {
        $ifaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($iface in $ifaces) {
            if ($iface.OperationalStatus -ne "Up") { continue }
            foreach ($addr in $iface.GetIPProperties().UnicastAddresses) {
                if ($addr.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                $ipStr = $addr.Address.ToString()
                if ($ipStr -like "127.*" -or $ipStr -like "169.254.*") { continue }
                $ip = $ipStr
                break
            }
            if ($ip -ne "Unknown") { break }
        }
    }
    catch {}

    $isAdmin = $false
    try {
        if (Get-Command fncIsAdmin -ErrorAction SilentlyContinue) {
            $isAdmin = fncIsAdmin
        }
        else {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $pri = New-Object Security.Principal.WindowsPrincipal($id)
            $isAdmin = $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    catch {}

    $hostType = "Unknown"
    try {
        if (Get-Command fncGetEnvProfile -ErrorAction SilentlyContinue) {
            $hostType = fncGetEnvProfile
        }
        else {
            $pt = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
            $hostType = switch ($pt) {
                1 { "Workstation" }
                2 { "Domain Controller" }
                default { "Server" }
            }
        }
    }
    catch {}

    $runId = ""
    $strategy = ""
    try { $runId = [string]$global:ProberState.RunContext.RunId } catch {}
    try { $strategy = fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "") } catch {}
    if (-not $runId) { $runId = [guid]::NewGuid().ToString() }

    return [pscustomobject]@{
        hostname  = $hostname
        ip        = $ip
        user      = $user
        privilege = if ($isAdmin) { "Admin Context" } else { "Low Priv Context" }
        hostType  = $hostType
        runId     = $runId
        strategy  = $strategy
    }
}

# ================================================================
# Internal: normalise a PS mapping array to camelCase objects
# ================================================================

function fncExportNormMappings {
    param([object[]]$Items, [bool]$IncludeTactic = $false)

    $out = @()
    foreach ($item in @($Items)) {
        if ($null -eq $item) { continue }

        $id = ""
        $name = ""
        $url = ""
        $tac = ""

        try { $id = [string]$item.Id } catch {}
        try { $name = [string]$item.Name } catch {}
        try { $url = [string]$item.Url } catch {}
        try { $tac = [string]$item.Tactic } catch {}

        if (-not $id) { continue }

        if ($IncludeTactic) {
            $out += [pscustomobject]@{ id = $id; name = $name; url = $url; tactic = $tac }
        }
        else {
            $out += [pscustomobject]@{ id = $id; name = $name; url = $url }
        }
    }

    return $out
}

# ================================================================
# Internal: convert a finding to the HTML JS object shape
# ================================================================

function fncExportConvertFindingHtml {
    param([Parameter(Mandatory)]$F)

    $safeId = (fncExportStrProp $F "Id") -replace '[^A-Za-z0-9\-]', '-'

    $mitre = @(fncExportNormMappings (fncSafeArray $F.Mitre) -IncludeTactic $true)
    $cwe = @(fncExportNormMappings (fncSafeArray $F.CWE))
    $nist = @(fncExportNormMappings (fncSafeArray $F.NIST))
    $cis = @(fncExportNormMappings (fncSafeArray $F.CIS))

    $evidence = (@(fncSafeArray $F.Evidence) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join "`n"

    $time = ""
    try { if ($F.Timestamp) { $time = $F.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } } catch {}
    if (-not $time) { try { if ($F.FirstSeen) { $time = $F.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss") } } catch {} }
    if (-not $time) { $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }

    return [pscustomobject][ordered]@{
        id               = $safeId
        title            = fncExportStrProp $F "Title"
        category         = fncExportStrProp $F "Category"
        severity         = fncExportStrProp $F "Severity"
        status           = fncExportStrProp $F "Status"
        time             = $time
        cvss             = ""
        message          = fncExportStrProp $F "Message"
        recommendation   = fncExportStrProp $F "Recommendation"
        exploitation     = fncExportStrProp $F "Exploitation"
        remediation      = fncExportStrProp $F "Remediation"
        evidence         = $evidence
        sourceTests      = @(fncSafeArray $F.SourceTests)

        # arrays used by meta bubbles (normalizeFrameworkItem handles objects)
        mitre            = $mitre
        cwe              = $cwe
        nist             = $nist
        cis              = $cis

        # full object arrays used by detail columns
        mitreObjects     = $mitre
        cweObjects       = $cwe
        nistObjects      = $nist
        cisObjects       = $cis

        # flag fields (not currently set by the framework - default false)
        exploitAvailable = $false
        internetExposed  = $false
        privEscCandidate = $false

        # attack chain fields
        attackChainId    = ""
        attackStep       = 0
        attackPrev       = ""
        attackNext       = ""
        scope            = fncExportStrProp $F "Scope"
    }
}

# ================================================================
# Internal: sort findings Critical -> Info
# ================================================================

function fncExportSortedFindings {
    return @($global:ProberState.Findings.Values | Sort-Object {
            switch ([string]$_.Severity) {
                "Critical" { 0 } "High" { 1 } "Medium" { 2 } "Low" { 3 } "Info" { 4 } default { 5 }
            }
        })
}

# ================================================================
# Internal: severity summary
# ================================================================

function fncExportSeveritySummary {

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }

    foreach ($f in @($global:ProberState.Findings.Values)) {
        $s = [string]$f.Severity
        if ($counts.ContainsKey($s)) { $counts[$s]++ }
    }

    return $counts
}

# ================================================================
# fncExportFindingsToCsv
# ================================================================

function fncExportFindingsToCsv {
    param(
        [string]$Path = "",
        [switch]$Force
    )

    try { fncLog "INFO" "fncExportFindingsToCsv invoked" } catch {}

    $total = fncSafeCount $global:ProberState.Findings
    if ($total -eq 0) {
        fncExportWarn "No findings to export."
        return
    }

    fncExportStep ("Preparing CSV export ({0} finding(s))..." -f $total)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $Path = Join-Path (fncExportGetOutputDir) ("Findings_{0}.csv" -f $stamp)
    }

    fncExportStep ("Output path: {0}" -f $Path)

    if (-not (fncExportCheckPath -Path $Path -Force $Force -Format "CSV")) { return }

    fncExportStep "Building rows..."

    $rows = @()
    foreach ($f in @(fncExportSortedFindings)) {

        $mitreCsv = (@(fncSafeArray $f.Mitre)  | ForEach-Object { [string]$_.Id }) -join " | "
        $cweCsv = (@(fncSafeArray $f.CWE)    | ForEach-Object { [string]$_.Id }) -join " | "
        $nistCsv = (@(fncSafeArray $f.NIST)   | ForEach-Object { [string]$_.Id }) -join " | "
        $cisCsv = (@(fncSafeArray $f.CIS)    | ForEach-Object { [string]$_.Id }) -join " | "

        $rows += [pscustomobject]@{
            ExportedAt     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Id             = [string]$f.Id
            Category       = [string]$f.Category
            Title          = [string]$f.Title
            Severity       = [string]$f.Severity
            Status         = [string]$f.Status
            Host           = [string]$f.Host
            Message        = ([string]$f.Message) -replace "`r`n|`n|`r", " "
            Recommendation = ([string]$f.Recommendation) -replace "`r`n|`n|`r", " "
            Exploitation   = ([string]$f.Exploitation) -replace "`r`n|`n|`r", " "
            Remediation    = ([string]$f.Remediation) -replace "`r`n|`n|`r", " "
            Evidence       = (@(fncSafeArray $f.Evidence) -join " | ")
            SourceTests    = (@(fncSafeArray $f.SourceTests) -join ", ")
            MITRE          = $mitreCsv
            CWE            = $cweCsv
            NIST           = $nistCsv
            CIS            = $cisCsv
        }
    }

    fncExportStep ("Writing {0} row(s) to disk..." -f $rows.Count)

    try {
        $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force
        fncExportOk ("CSV export complete: {0}" -f $Path)
        try { fncLog "INFO" ("CSV export: {0} ({1} rows)" -f $Path, $rows.Count) } catch {}
    }
    catch {
        fncExportFail ("CSV export failed: {0}" -f $_.Exception.Message)
        try { fncLogException $_.Exception "CSV export" } catch {}
    }
}

# ================================================================
# fncExportFindingsToJson
# ================================================================

function fncExportFindingsToJson {
    param(
        [string]$Path = "",
        [switch]$Force
    )

    try { fncLog "INFO" "fncExportFindingsToJson invoked" } catch {}

    $total = fncSafeCount $global:ProberState.Findings
    if ($total -eq 0) {
        fncExportWarn "No findings to export."
        return
    }

    fncExportStep ("Preparing JSON export ({0} finding(s))..." -f $total)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $Path = Join-Path (fncExportGetOutputDir) ("Findings_{0}.json" -f $stamp)
    }

    fncExportStep ("Output path: {0}" -f $Path)

    if (-not (fncExportCheckPath -Path $Path -Force $Force -Format "JSON")) { return }

    fncExportStep "Building run context..."
    $counts = fncExportSeveritySummary
    $sorted = @(fncExportSortedFindings)
    $runCtx = fncExportGetRunContext

    fncExportStep "Converting findings..."
    $findingRows = foreach ($f in $sorted) {

        $mitre = @(@(fncSafeArray $f.Mitre) | ForEach-Object {
                [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; Tactic = [string]$_.Tactic; Url = [string]$_.Url }
            })
        $cwe = @(@(fncSafeArray $f.CWE)   | ForEach-Object {
                [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; Url = [string]$_.Url }
            })
        $nist = @(@(fncSafeArray $f.NIST)  | ForEach-Object {
                [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; Url = [string]$_.Url }
            })
        $cis = @(@(fncSafeArray $f.CIS)   | ForEach-Object {
                [pscustomobject]@{ Id = [string]$_.Id; Name = [string]$_.Name; Url = [string]$_.Url }
            })

        $ts = ""
        try { if ($f.Timestamp) { $ts = $f.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss") } } catch {}
        $fs = ""
        try { if ($f.FirstSeen) { $fs = $f.FirstSeen.ToString("yyyy-MM-ddTHH:mm:ss") } } catch {}
        $ls = ""
        try { if ($f.LastSeen) { $ls = $f.LastSeen.ToString("yyyy-MM-ddTHH:mm:ss") } } catch {}

        [pscustomobject]@{
            Id             = [string]$f.Id
            Title          = [string]$f.Title
            Category       = [string]$f.Category
            Severity       = [string]$f.Severity
            Status         = [string]$f.Status
            Host           = [string]$f.Host
            Message        = [string]$f.Message
            Recommendation = [string]$f.Recommendation
            Exploitation   = [string]$f.Exploitation
            Remediation    = [string]$f.Remediation
            Evidence       = @(fncSafeArray $f.Evidence)
            SourceTests    = @(fncSafeArray $f.SourceTests)
            Timestamp      = $ts
            FirstSeen      = $fs
            LastSeen       = $ls
            Mappings       = [pscustomobject]@{
                MitreAttack = $mitre
                CWE         = $cwe
                NIST        = $nist
                CIS         = $cis
            }
        }
    }

    $document = [pscustomobject]@{
        Schema     = "thePr0b3r-findings-v1"
        ExportedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        Run        = [pscustomobject]@{
            RunId    = $runCtx.runId
            Host     = $runCtx.hostname
            User     = $runCtx.user
            Strategy = $runCtx.strategy
        }
        Summary    = [pscustomobject]@{
            Total    = @($findingRows).Count
            Critical = $counts["Critical"]
            High     = $counts["High"]
            Medium   = $counts["Medium"]
            Low      = $counts["Low"]
            Info     = $counts["Info"]
        }
        Findings   = @($findingRows)
    }

    fncExportStep "Serialising to JSON..."

    try {
        $json = $document | ConvertTo-Json -Depth 10
        fncExportStep "Writing to disk..."
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)
        fncExportOk ("JSON export complete: {0}" -f $Path)
        fncExportOk ("  {0} finding(s)  |  Critical: {1}  High: {2}  Medium: {3}  Low: {4}  Info: {5}" -f `
            @($findingRows).Count, $counts["Critical"], $counts["High"], $counts["Medium"], $counts["Low"], $counts["Info"])
        try { fncLog "INFO" ("JSON export: {0} ({1} findings)" -f $Path, @($findingRows).Count) } catch {}
    }
    catch {
        fncExportFail ("JSON export failed: {0}" -f $_.Exception.Message)
        try { fncLogException $_.Exception "JSON export" } catch {}
    }
}

# ================================================================
# fncExportFindingsToHtml
# ================================================================

function fncExportFindingsToHtml {
    param(
        [string]$Path = "",
        [switch]$Force
    )

    try { fncLog "INFO" "fncExportFindingsToHtml invoked" } catch {}

    $total = fncSafeCount $global:ProberState.Findings
    if ($total -eq 0) {
        fncExportWarn "No findings to export."
        return
    }

    fncExportStep ("Preparing HTML export ({0} finding(s))..." -f $total)

    # Locate template
    $templatePath = Join-Path (Join-Path (fncExportGetRepoRoot) "data") "ThePr0b3r_blank.html"
    fncExportStep ("Template: {0}" -f $templatePath)

    if (-not (Test-Path -LiteralPath $templatePath)) {
        fncExportFail ("HTML template not found: {0}" -f $templatePath)
        try { fncLog "ERROR" ("HTML template missing: {0}" -f $templatePath) } catch {}
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $Path = Join-Path (fncExportGetOutputDir) ("ThePr0b3r_Report_{0}.html" -f $stamp)
    }

    fncExportStep ("Output path: {0}" -f $Path)

    if (-not (fncExportCheckPath -Path $Path -Force $Force -Format "HTML")) { return }

    try {
        fncExportStep "Loading template..."
        $html = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8

        # Validate placeholders exist
        if ($html -notmatch "const\s+FINDINGS\s*=\s*\[\s*\]\s*;") {
            fncExportFail "HTML template is missing the 'const FINDINGS = [];' placeholder."
            return
        }
        if ($html -notmatch "const\s+RUN_CONTEXT\s*=\s*\{\s*\}\s*;") {
            fncExportFail "HTML template is missing the 'const RUN_CONTEXT = {};' placeholder."
            return
        }
        if ($html -notmatch "const\s+CIS_AUDIT\s*=\s*\{\s*\}\s*;") {
            fncExportFail "HTML template is missing the 'const CIS_AUDIT = {};' placeholder."
            return
        }

        # Convert findings
        fncExportStep "Converting findings to HTML objects..."
        $converted = @(fncExportSortedFindings | ForEach-Object { fncExportConvertFindingHtml -F $_ })
        fncExportStep ("{0} finding(s) converted." -f $converted.Count)

        # Run context
        fncExportStep "Building run context..."
        $runCtx = fncExportGetRunContext
        $runJson = $runCtx | ConvertTo-Json -Compress -Depth 3

        fncExportStep "Serialising data..."
        $findJson = $converted | ConvertTo-Json -Depth 10 -Compress

        fncExportStep "Injecting data into template..."
        $html = [regex]::Replace(
            $html,
            "const\s+FINDINGS\s*=\s*\[\s*\]\s*;",
            ("const FINDINGS = {0};" -f $findJson)
        )

        $html = [regex]::Replace(
            $html,
            "const\s+RUN_CONTEXT\s*=\s*\{\s*\}\s*;",
            ("const RUN_CONTEXT = {0};" -f $runJson)
        )

        $cisAuditJson = try {
            if ($global:ProberState.PSObject.Properties.Name -contains "CISAuditStats" -and
                $global:ProberState.CISAuditStats) {
                $global:ProberState.CISAuditStats | ConvertTo-Json -Compress -Depth 3
            } else { "{}" }
        } catch { "{}" }

        $html = [regex]::Replace(
            $html,
            "const\s+CIS_AUDIT\s*=\s*\{\s*\}\s*;",
            ("const CIS_AUDIT = {0};" -f $cisAuditJson)
        )

        fncExportStep "Writing report to disk..."
        $html | Set-Content -LiteralPath $Path -Encoding UTF8 -Force

        fncExportOk ("HTML export complete: {0}" -f $Path)
        fncExportOk ("  {0} finding(s)  |  Run: {1}" -f $converted.Count, $runCtx.runId)
        try { fncLog "INFO" ("HTML export: {0} ({1} findings)" -f $Path, $converted.Count) } catch {}

        # Auto-open on Windows
        try {
            $_isWin = $true
            if (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
                if ($IsLinux -or $IsMacOS) { $_isWin = $false }
            }
            if ($_isWin) { Start-Process -FilePath $Path }
        }
        catch {}
    }
    catch {
        fncExportFail ("HTML export failed: {0}" -f $_.Exception.Message)
        try { fncLogException $_.Exception "HTML export" } catch {}
    }
}

# ================================================================
Export-ModuleMember -Function @(
    "fncExportFindingsToCsv",
    "fncExportFindingsToJson",
    "fncExportFindingsToHtml"
)
