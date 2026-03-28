# ================================================================
# Module  : Output.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Variable Banner -Scope Global -ErrorAction SilentlyContinue)) {
    $global:Banner = @'
 ________  __                        _______              ______   __         ______            
|        \|  \                      |       \            /      \ |  \       /      \           
 \$$$$$$$$| $$____    ______        | $$$$$$$\  ______  |  $$$$$$\| $$____  |  $$$$$$\  ______  
   | $$   | $$    \  /      \       | $$__/ $$ /      \ | $$$\| $$| $$    \  \$$__| $$ /      \ 
   | $$   | $$$$$$$\|  $$$$$$\      | $$    $$|  $$$$$$\| $$$$\ $$| $$$$$$$\  |     $$|  $$$$$$\
   | $$   | $$  | $$| $$    $$      | $$$$$$$ | $$   \$$| $$\$$\$$| $$  | $$ __\$$$$$\| $$   \$$             2
   | $$   | $$  | $$| $$$$$$$$      | $$      | $$      | $$_\$$$$| $$__/ $$|  \__| $$| $$      
   | $$   | $$  | $$ \$$     \      | $$      | $$       \$$  \$$$| $$    $$ \$$    $$| $$      
    \$$    \$$   \$$  \$$$$$$$       \$$       \$$        \$$$$$$  \$$$$$$$   \$$$$$$  \$$      
                                                                    
                                                    )  (  (    (
                                                    (  )  () @@  )  (( (
                                                (      (  )( @@  (  )) ) (
                                            (    (  ( ()( /---\   (()( (
                _______                            )  ) )(@ !O O! )@@  ( ) ) )
                <   ____)                      ) (  ( )( ()@ \ o / (@@@@@ ( ()( )
            /--|  |(  o|                     (  )  ) ((@@(@@ !o! @@@@(@@@@@)() (
            |   >   \___|                      ) ( @)@@)@ /---\-/---\ )@@@@@()( )
            |  /---------+                    (@@@@)@@@( // /-----\ \\ @@@)@@@@@(  .
            | |    \ =========______/|@@@@@@@@@@@@@(@@@ // @ /---\ @ \\ @(@@@(@@@ .  .
            |  \   \\=========------\|@@@@@@@@@@@@@@@@@ O @@@ /-\ @@@ O @@(@@)@@ @   .
            |   \   \----+--\-)))           @@@@@@@@@@ !! @@@@ % @@@@ !! @@)@@@ .. .
            |   |\______|_)))/             .    @@@@@@ !! @@ /---\ @@ !! @@(@@@ @ . .
            \__==========           *        .    @@ /MM  /\O   O/\  MM\ @@@@@@@. .
                |   |-\   \          (       .      @ !!!  !! \-/ !!  !!! @@@@@ .
                |   |  \   \          )   -cfbd-   .  @@@@ !!     !!  .(. @.  .. .
                |   |   \   \        (    /   .(  . \)). ( |O  )( O! @@@@ . )      .
                |   |   /   /         ) (      )).  ((  .) !! ((( !! @@ (. ((. .   .
                |   |  /   /   ()  ))   ))   .( ( ( ) ). ( !!  )( !! ) ((   ))  ..
                |   |_<   /   ( ) ( (  ) )   (( )  )).) ((/ |  (  | \(  )) ((. ).
            ____<_____\\__\__(___)_))_((_(____))__(_(___.oooO_____Oooo.(_(_)_)((_     
                        
                        THE Pr0b3r  ::  {0}
                ----------------------------------------------------------------
                ::          https://github.com/deannreid/ThePr0b3r            ::
                ----------------------------------------------------------------
'@
}

if (-not (Get-Variable CurrentBlurb -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CurrentBlurb = "Operationalising bad decisions... safely."
}

if (-not $global:ProberState) {
    return
}

if (-not $global:ProberState.Config) {
    return
}

if ($global:ProberState.Config.PSObject.Properties.Name -notcontains "DEBUG") {
    $global:ProberState.Config | Add-Member -MemberType NoteProperty -Name "DEBUG" -Value $false
}

if ($global:ProberState.Config.PSObject.Properties.Name -notcontains "ConsoleLogLevel") {
    $global:ProberState.Config | Add-Member -MemberType NoteProperty -Name "ConsoleLogLevel" -Value "NONE"
}

function fncWriteColour {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][System.ConsoleColor]$Colour,
        [switch]$NoNewLine
    )

    try {
        if ($NoNewLine) { Write-Host $Text -ForegroundColor $Colour -NoNewline }
        else { Write-Host $Text -ForegroundColor $Colour }
    }
    catch {
        if ($NoNewLine) { Write-Host $Text -NoNewline }
        else { Write-Host $Text }
    }
}

function fncColourLine {

    param(
        [string]$Name,
        [string]$Value,
        [bool]$IsRisk
    )

    if (fncCommandExists "fncWriteColour") {

        fncWriteColour ("  - {0,-20}: " -f $Name) ([System.ConsoleColor]::White) -NoNewLine

        if ($IsRisk) {
            fncWriteColour $Value ([System.ConsoleColor]::Red)
        }
        else {
            fncWriteColour $Value ([System.ConsoleColor]::Green)
        }

    }
    else {
        Write-Host ("  - {0,-20}: {1}" -f $Name, $Value)
    }
}

function fncPrintSectionHeader {
    param(
        [Parameter(Mandatory = $true)][string]$Title
    )

    # Delegate to the strategy-aware renderer when available (loaded after this module)
    if (Get-Command fncRenderSectionHeader -ErrorAction SilentlyContinue) {
        fncRenderSectionHeader -Title $Title
        return
    }

    # Fallback used only if UI.Render.psm1 has not loaded yet
    $safeTitle = try { fncSafeString $Title } catch { "$Title" }
    Write-Host ""
    Write-Host ("=========|| {0} ||=========" -f $safeTitle)
}

# ================================================================
# Function: fncPrintMessage
# Purpose : Prints formatted console messages and logs them
# Notes   : Supports additional output key indicators used by fncPrintKey
# ================================================================
function fncPrintMessage {

    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet("success", "info", "warning", "error", "debug", "plain")]
        [string]$Level = "info"
    )

    $logLevelMap = @{
        "success" = "INFO"
        "info"    = "INFO"
        "warning" = "WARN"
        "error"   = "ERROR"
        "debug"   = "DEBUG"
        "plain"   = "INFO"
    }

    $mappedLevel = $logLevelMap[$Level]

    # ------------------------------------------------------------
    # Write to framework log
    # ------------------------------------------------------------
    try {
        if (Get-Command fncLog -ErrorAction SilentlyContinue) {
            fncLog $mappedLevel $Message
        }
    }
    catch {}

    # ------------------------------------------------------------
    # Plain messages ALWAYS display
    # ------------------------------------------------------------
    if ($Level -ne "plain") {

        if (-not (fncShouldConsoleLog $mappedLevel)) {
            return
        }
    }

    # ------------------------------------------------------------
    # Determine prefix and colour
    # ------------------------------------------------------------
    $prefix = ""
    $colour = [System.ConsoleColor]::White

    switch ($Level) {

        "success" { $prefix = "[+]"; $colour = [System.ConsoleColor]::Green }
        "info" { $prefix = "[i]"; $colour = [System.ConsoleColor]::Cyan }
        "warning" { $prefix = "[!]"; $colour = [System.ConsoleColor]::Yellow }
        "error" { $prefix = "[-]"; $colour = [System.ConsoleColor]::Red }

        "debug" {

            $prefix = "[d]"
            $colour = [System.ConsoleColor]::DarkGray

            $debugOn = $false

            try {
                if ($global:ProberState.Config.DEBUG -eq $true) {
                    $debugOn = $true
                }
            }
            catch {}

            if (-not $debugOn) { return }
        }

        "plain" {
            $prefix = ""
            $colour = [System.ConsoleColor]::White
        }
    }

    # ------------------------------------------------------------
    # Print output
    # ------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($prefix)) {
        fncWriteColour $Message $colour
    }
    else {
        fncWriteColour ("{0} {1}" -f $prefix, $Message) $colour
    }
}

function fncPrintKey {

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" "Rendering output key legend" } } catch {}

    $divider = "  " + ("-" * 51)

    Write-Host ""
    Write-Host "  ====================================================" -ForegroundColor Blue
    Write-Host "                      OUTPUT KEY                      " -ForegroundColor Blue
    Write-Host "  ====================================================" -ForegroundColor Blue

    # ── Output Symbols ──────────────────────────────────────
    Write-Host ""
    Write-Host "  Output Symbols" -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host "[!] " -NoNewline -ForegroundColor Red
    Write-Host "Special privilege or misconfiguration"
    Write-Host "  " -NoNewline
    Write-Host "[!!]" -NoNewline -ForegroundColor Yellow
    Write-Host " Warning or configuration that should be reviewed"
    Write-Host "  " -NoNewline
    Write-Host "[+] " -NoNewline -ForegroundColor Green
    Write-Host "Protection enabled / well configured"
    Write-Host "  " -NoNewline
    Write-Host "[~] " -NoNewline -ForegroundColor Cyan
    Write-Host "Active user, service, or object"
    Write-Host "  " -NoNewline
    Write-Host "[X] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Disabled user, service, or object"
    Write-Host "  " -NoNewline
    Write-Host "[>] " -NoNewline -ForegroundColor Magenta
    Write-Host "Link, reference, or relationship"
    Write-Host "  " -NoNewline
    Write-Host "[i] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Informational output"

    # ── Maturity ─────────────────────────────────────────────
    Write-Host ""
    Write-Host "  Maturity  (detection quality)" -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host "[STABLE]       " -NoNewline -ForegroundColor Green
    Write-Host "Comprehensive, multi-signal, handles edge cases"
    Write-Host "  " -NoNewline
    Write-Host "[BETA]         " -NoNewline -ForegroundColor Yellow
    Write-Host "Functional but has known coverage gaps"
    Write-Host "  " -NoNewline
    Write-Host "[EXPERIMENTAL] " -NoNewline -ForegroundColor DarkYellow
    Write-Host "Thin signal - significant detection gaps"
    Write-Host "  " -NoNewline
    Write-Host "[DEPRECATED]   " -NoNewline -ForegroundColor Red
    Write-Host "Outdated approach - scheduled for replacement"

    # ── Risk (OPSEC) ─────────────────────────────────────────
    Write-Host ""
    Write-Host "  Risk  (OPSEC / EDR visibility)" -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host "[SAFE]      " -NoNewline -ForegroundColor Green
    Write-Host "Pure config reads - no detectable telemetry"
    Write-Host "  " -NoNewline
    Write-Host "[LOW]       " -NoNewline -ForegroundColor DarkGreen
    Write-Host "WMI / PS cmdlets - minimal signal"
    Write-Host "  " -NoNewline
    Write-Host "[MEDIUM]    " -NoNewline -ForegroundColor Yellow
    Write-Host "Process spawns or broad enumeration - may trigger logging"
    Write-Host "  " -NoNewline
    Write-Host "[HIGH]      " -NoNewline -ForegroundColor DarkRed
    Write-Host "LSASS, credential APIs, SAM access - likely EDR alert"
    Write-Host "  " -NoNewline
    Write-Host "[DANGEROUS] " -NoNewline -ForegroundColor Magenta
    Write-Host "Exploit-style activity - expect detection"

    # ── Strategy ─────────────────────────────────────────────
    Write-Host ""
    Write-Host "  Strategy" -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host "[DEFENSIVE] " -NoNewline -ForegroundColor Cyan
    Write-Host "Validates security controls are correctly in place"
    Write-Host "  " -NoNewline
    Write-Host "[OFFENSIVE] " -NoNewline -ForegroundColor Red
    Write-Host "Enumerates attack surface or exploitable weaknesses"

    Write-Host ""
    Write-Host "  ====================================================" -ForegroundColor Blue
    Write-Host ""
}

function fncTestMessage {

    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet("info", "warning", "specpriv", "proten", "active", "disabled", "link", "section")]
        [string]$Level = "info"
    )

    $logLevelMap = @{
        "info"     = "INFO"
        "warning"  = "WARN"
        "specpriv" = "WARN"
        "proten"   = "INFO"
        "active"   = "INFO"
        "disabled" = "INFO"
        "link"     = "INFO"
        "section"  = "INFO"
    }

    $mappedLevel = $logLevelMap[$Level]

    # Always write to framework log
    try {
        if (Get-Command fncLog -ErrorAction SilentlyContinue) {
            fncLog $mappedLevel $Message
        }
    }
    catch {}

    $prefix = ""
    $colour = [System.ConsoleColor]::White

    switch ($Level) {
        "info" { $prefix = "[i]"; $colour = "DarkCyan" }
        "warning" { $prefix = "[!!]"; $colour = "Yellow" }
        "specpriv" { $prefix = "[!]"; $colour = "Red" }
        "proten" { $prefix = "[+]"; $colour = "Green" }
        "active" { $prefix = "[~]"; $colour = "Cyan" }
        "disabled" { $prefix = "[X]"; $colour = "DarkGray" }
        "link" { $prefix = "[>]"; $colour = "Magenta" }
        "section" { $prefix = "[#]"; $colour = "Blue" }
    }

    if ([string]::IsNullOrWhiteSpace($prefix)) {
        fncWriteColour $Message $colour
    }
    else {
        fncWriteColour ("{0} {1}" -f $prefix, $Message) $colour
    }
}

Export-ModuleMember -Function @(
    "fncWriteColour",
    "fncColourLine",
    "fncPrintSectionHeader",
    "fncPrintMessage",
    "fncPrintKey",
    "fncTestMessage"
)