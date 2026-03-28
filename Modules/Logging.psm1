# ================================================================
# Module: Logging.psm1
# ================================================================

$script:LogLevels = @{
    NONE  = 0
    ERROR = 1
    WARN  = 2
    INFO  = 3
    DEBUG = 4
}

# ------------------------------------------------------------
# Determine if console output should occur
# ------------------------------------------------------------
function fncShouldConsoleLog {

    param([string]$Level)

    if (-not $global:ProberState) { return $false }
    if (-not $global:ProberState.Config) { return $false }

    $consoleLevel = $global:ProberState.Config.ConsoleLogLevel

    if ([string]::IsNullOrWhiteSpace($consoleLevel)) {
        return $false
    }

    $consoleLevel = $consoleLevel.ToUpper()
    $Level = $Level.ToUpper()

    if ($consoleLevel -eq "NONE") {
        return $false
    }

    if (-not $script:LogLevels.ContainsKey($consoleLevel)) {
        return $false
    }

    if (-not $script:LogLevels.ContainsKey($Level)) {
        return $false
    }

    return ($script:LogLevels[$Level] -le $script:LogLevels[$consoleLevel])
}

# ------------------------------------------------------------
# Core Logging Function
# ------------------------------------------------------------
function fncLog {

    param(
        [string]$Level,
        [string]$Message,
        [hashtable]$Metadata = $null
    )

    try {

        $Level = $Level.ToUpper()

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

        $line = "{0} [{1}] {2}" -f $timestamp, $Level, $Message

        # ---------------------------------
        # Append structured metadata
        # ---------------------------------
        if ($Metadata) {

            $pairs = $Metadata.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$($_.Value)"
            }

            $metaString = $pairs -join " "

            $line = "$line | $metaString"
        }

        $logFile = $global:ProberState.Runtime.LogFile

        if ($logFile) {
            [System.IO.File]::AppendAllText($logFile, "$line`n")
        }

        if ((fncShouldConsoleLog $Level) -eq $true) {

            switch ($Level) {

                "ERROR" { Write-Host $line -ForegroundColor Red }
                "WARN" { Write-Host $line -ForegroundColor Yellow }
                "DEBUG" { Write-Host $line -ForegroundColor DarkGray }

                default { Write-Host $line }
            }
        }

    }
    catch {
        Write-Host "Logging failure: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ------------------------------------------------------------
# Console Message Helper
# ------------------------------------------------------------
function fncPrintMessage {

    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Level = $Level.ToUpper()

    fncLog $Level $Message
}

# ------------------------------------------------------------
# Banner Logger
# ------------------------------------------------------------
function fncLogBanner {

    param([string]$Title)

    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    fncLog "INFO" "============================================================"
    fncLog "INFO" "$Title - $time"
    fncLog "INFO" "============================================================"
}

# ------------------------------------------------------------
# Exception Logger
# ------------------------------------------------------------
function fncLogException {

    param(
        [object]$Exception,
        [string]$Source = "Unknown"
    )

    fncLog "ERROR" "Exception in $Source"
    fncLog "ERROR" $Exception.Message
    fncLog "DEBUG" $Exception.ToString()
}