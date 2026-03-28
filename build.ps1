#Requires -Version 5.1
<#
.SYNOPSIS
    Builds self-contained distributions of THE Pr0b3r.

.DESCRIPTION
    Windows  : bundles project files + a launcher that calls the built-in
               powershell.exe (5.1) -- no runtime download needed.
               Produces a .zip, and a self-extracting .exe if 7-Zip is installed.

    Linux / macOS : downloads PowerShell Core for the target platform, bundles
               it with all project files, and produces a .tar.gz plus a
               self-extracting .run file (no external tools required on target).

.PARAMETER Target
    Platform(s) to build. One of:
      all, win-x64, linux-x64, linux-arm64, osx-x64, osx-arm64
    Defaults to "all".

.PARAMETER PwshVersion
    PowerShell Core version to bundle for Linux/macOS. Defaults to 7.4.7 (LTS).

.PARAMETER OutputDir
    Output directory. Defaults to ./dist

.PARAMETER Clean
    Remove and recreate the output directory before building.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Target linux-x64
    .\build.ps1 -Target win-x64 -Clean
    .\build.ps1 -Target linux-x64 -PwshVersion 7.5.0
#>
param(
    [ValidateSet("all", "win-x64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64")]
    [string]$Target = "all",

    [string]$PwshVersion = "7.4.7",

    [string]$OutputDir = "dist",

    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$OutputPath  = Join-Path $ProjectRoot $OutputDir
$CachePath   = Join-Path $OutputPath ".cache"

# UTF-8 without BOM (required for shell scripts and consistent text files)
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# -- Project file manifest -----------------------------------------------------

$IncludeFiles = @(
    "thePr0b3r.ps1",
    "README.md",
    "CHANGELOG.MD",
    "TEST_AUTHORING.md"
)
$IncludeDirs = @("Modules", "Tests", "data")

# -- PowerShell Core download URLs (Linux / macOS only) ------------------------

$PwshUrls = @{
    "linux-x64"   = "https://github.com/PowerShell/PowerShell/releases/download/v${PwshVersion}/powershell-${PwshVersion}-linux-x64.tar.gz"
    "linux-arm64" = "https://github.com/PowerShell/PowerShell/releases/download/v${PwshVersion}/powershell-${PwshVersion}-linux-arm64.tar.gz"
    "osx-x64"     = "https://github.com/PowerShell/PowerShell/releases/download/v${PwshVersion}/powershell-${PwshVersion}-osx-x64.tar.gz"
    "osx-arm64"   = "https://github.com/PowerShell/PowerShell/releases/download/v${PwshVersion}/powershell-${PwshVersion}-osx-arm64.tar.gz"
}

# -- Setup ---------------------------------------------------------------------

if ($Clean -and (Test-Path $OutputPath)) {
    Write-Host "Cleaning output directory..." -ForegroundColor DarkGray
    Remove-Item $OutputPath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
New-Item -ItemType Directory -Force -Path $CachePath  | Out-Null

$BuildTargets = if ($Target -eq "all") {
    @("win-x64") + [string[]]$PwshUrls.Keys
} else {
    [string[]]@($Target)
}

# -- Helpers -------------------------------------------------------------------

function Write-Step { param([string]$Msg) Write-Host "  --> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [!!] $Msg" -ForegroundColor Yellow }

function Copy-ProjectFiles {
    param([string]$DestDir)

    foreach ($f in $IncludeFiles) {
        $src = Join-Path $ProjectRoot $f
        if (Test-Path $src) { Copy-Item $src $DestDir }
    }
    foreach ($d in $IncludeDirs) {
        $src = Join-Path $ProjectRoot $d
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $DestDir $d) -Recurse
        }
    }

    # Reset config to safe defaults for distribution
    '{"Strategy":"blue","logger":"silent"}' |
        Set-Content -Path (Join-Path $DestDir "prober.config.json") -Encoding UTF8

    # Pre-create runtime directories
    New-Item -ItemType Directory -Force -Path (Join-Path $DestDir "Logs")    | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $DestDir "exports") | Out-Null
}

function Get-PwshCore {
    param([string]$Platform, [string]$DestDir)

    $url      = $PwshUrls[$Platform]
    $fileName = Split-Path $url -Leaf
    $cached   = Join-Path $CachePath $fileName

    if (-not (Test-Path $cached)) {
        Write-Step "Downloading PowerShell $PwshVersion for $Platform..."
        Invoke-WebRequest -Uri $url -OutFile $cached -UseBasicParsing
    } else {
        Write-Step "Using cached PowerShell $PwshVersion for $Platform"
    }

    $pwshDir = Join-Path $DestDir "pwsh"
    New-Item -ItemType Directory -Force -Path $pwshDir | Out-Null

    # tar ships with Windows 10 1803+ and all Unix systems
    & tar xzf $cached -C $pwshDir
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed for $cached" }
}

# -- Windows build -------------------------------------------------------------
# Uses built-in Windows PowerShell 5.1 (powershell.exe) -- nothing to bundle.

function Build-Windows {
    param([string]$Arch = "x64")

    $platform   = "win-$Arch"
    $stagingDir = Join-Path $OutputPath "staging-$platform"
    $outputZip  = Join-Path $OutputPath "thePr0b3r-$platform.zip"
    $outputExe  = Join-Path $OutputPath "thePr0b3r-$platform.exe"

    Write-Host "`nBuilding $platform (PowerShell 5.1 / built-in)..." -ForegroundColor Magenta

    if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

    Write-Step "Copying project files..."
    Copy-ProjectFiles -DestDir $stagingDir

    # Batch launcher -- uses the system powershell.exe (PS 5.1)
    $bat = @'
@echo off
setlocal
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0thePr0b3r.ps1" %*
endlocal
'@
    [System.IO.File]::WriteAllText((Join-Path $stagingDir "thePr0b3r.bat"), $bat, $Utf8NoBom)

    # ZIP archive
    Write-Step "Creating ZIP archive..."
    if (Test-Path $outputZip) { Remove-Item $outputZip -Force }
    Compress-Archive -Path "$stagingDir\*" -DestinationPath $outputZip -CompressionLevel Optimal
    Write-Ok "ZIP : $outputZip"

    # Self-extracting EXE via 7-Zip SFX (optional -- requires 7-Zip on build machine)
    $sevenZipExe = @(
        (Get-Command "7z.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "C:\Program Files\7-Zip\7z.exe",
        "C:\Program Files (x86)\7-Zip\7z.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

    if ($sevenZipExe) {
        $sfxModule = Join-Path (Split-Path $sevenZipExe) "7zSD.sfx"

        if (Test-Path $sfxModule) {
            Write-Step "Creating self-extracting EXE with 7-Zip..."

            $sfxConfig = ";!@Install@!UTF-8!`nTitle=`"THE Pr0b3r`"`nRunProgram=`"thePr0b3r.bat`"`n;!@InstallEnd@!"
            $tempArchive = Join-Path $OutputPath "._tmp_$platform.7z"
            $tempConfig  = Join-Path $OutputPath "._tmp_sfx.cfg"

            try {
                [System.IO.File]::WriteAllText($tempConfig, $sfxConfig, $Utf8NoBom)
                & $sevenZipExe a $tempArchive "$stagingDir\*" -r -mx5 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "7-Zip archive creation failed" }

                # Binary concat: SFX module + config + archive = self-extracting EXE
                $outStream = [System.IO.File]::OpenWrite($outputExe)
                try {
                    foreach ($src in @($sfxModule, $tempConfig, $tempArchive)) {
                        $bytes = [System.IO.File]::ReadAllBytes($src)
                        $outStream.Write($bytes, 0, $bytes.Length)
                    }
                } finally { $outStream.Close() }

                Write-Ok "EXE : $outputExe"
            } finally {
                Remove-Item $tempArchive, $tempConfig -ErrorAction SilentlyContinue
            }
        } else {
            Write-Warn "7zSD.sfx not found next to 7z.exe -- ZIP only (no EXE)"
        }
    } else {
        Write-Warn "7-Zip not found -- ZIP only (install 7-Zip on this machine to also produce an EXE)"
    }

    Remove-Item $stagingDir -Recurse -Force
}

# -- Linux / macOS build -------------------------------------------------------
# Bundles PowerShell Core so the target machine needs nothing pre-installed.

function Build-Unix {
    param([string]$Platform)

    $stagingDir = Join-Path $OutputPath "staging-$Platform"
    $outputTar  = Join-Path $OutputPath "thePr0b3r-$Platform.tar.gz"
    $outputRun  = Join-Path $OutputPath "thePr0b3r-$Platform.run"

    Write-Host "`nBuilding $Platform (bundled PowerShell $PwshVersion)..." -ForegroundColor Magenta

    if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

    Get-PwshCore -Platform $Platform -DestDir $stagingDir

    Write-Step "Copying project files..."
    Copy-ProjectFiles -DestDir $stagingDir

    # Shell launcher -- single-quoted here-string keeps $ chars literal
    $launchSh = @'
#!/bin/sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PWSH="$DIR/pwsh/pwsh"
if [ ! -x "$PWSH" ]; then chmod +x "$PWSH" 2>/dev/null || true; fi
exec "$PWSH" -ExecutionPolicy Bypass -NoProfile -File "$DIR/thePr0b3r.ps1" "$@"
'@
    $launchSh = $launchSh.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllBytes((Join-Path $stagingDir "launch.sh"),    $Utf8NoBom.GetBytes($launchSh))
    [System.IO.File]::WriteAllBytes((Join-Path $stagingDir "thePr0b3r.sh"), $Utf8NoBom.GetBytes($launchSh))

    # TAR.GZ
    Write-Step "Creating tar.gz archive..."
    if (Test-Path $outputTar) { Remove-Item $outputTar -Force }
    & tar czf $outputTar -C $stagingDir .
    if ($LASTEXITCODE -ne 0) { throw "tar failed creating $outputTar" }
    Write-Ok "TAR : $outputTar"

    # Self-extracting .run -- shell header prepended to the raw tar.gz bytes.
    # tail -n +SKIP skips the header lines and streams the binary payload to tar.
    # SKIP_PLACEHOLDER is fixed-width so replacing it does not change the line count.
    Write-Step "Creating self-extracting .run file..."

    $headerTemplate = @'
#!/bin/sh
# THE Pr0b3r - self-extracting bundle
# Usage: chmod +x thePr0b3r-PLATFORM.run && ./thePr0b3r-PLATFORM.run [options]
set -e
EXTRACT_DIR=$(mktemp -d /tmp/.pr0b3r-XXXXXXXX)
echo "[*] Extracting THE Pr0b3r..."
SKIP=SKIP_PLACEHOLDER
tail -n +"$SKIP" "$0" | tar xz -C "$EXTRACT_DIR" 2>/dev/null
find "$EXTRACT_DIR/pwsh" -name "pwsh" -exec chmod +x {} \; 2>/dev/null || true
chmod +x "$EXTRACT_DIR/launch.sh" 2>/dev/null || true
echo "[*] Launching..."
exec "$EXTRACT_DIR/launch.sh" "$@"
exit 0
'@
    $headerTemplate = $headerTemplate.Replace("`r`n", "`n").Replace("`r", "`n")

    $lineCount   = ($headerTemplate.TrimEnd("`n") -split "`n").Count
    $skipLine    = $lineCount + 1
    # Pad to same char-width as placeholder so line count stays constant
    $paddedSkip  = $skipLine.ToString().PadLeft("SKIP_PLACEHOLDER".Length)
    $finalHeader = $headerTemplate.Replace("SKIP_PLACEHOLDER", $paddedSkip)

    $headerBytes  = $Utf8NoBom.GetBytes($finalHeader)
    $archiveBytes = [System.IO.File]::ReadAllBytes($outputTar)

    $stream = [System.IO.File]::OpenWrite($outputRun)
    try {
        $stream.Write($headerBytes,  0, $headerBytes.Length)
        $stream.Write($archiveBytes, 0, $archiveBytes.Length)
    } finally { $stream.Close() }

    Write-Ok "RUN : $outputRun"
    Write-Host "      chmod +x thePr0b3r-$Platform.run && ./thePr0b3r-$Platform.run" -ForegroundColor DarkGray

    Remove-Item $stagingDir -Recurse -Force
}

# -- Main ----------------------------------------------------------------------

Write-Host "`nTHE Pr0b3r - Build Script" -ForegroundColor Cyan
Write-Host "Output    : $OutputPath"
Write-Host "Targets   : $($BuildTargets -join ', ')"
Write-Host "Unix pwsh : $PwshVersion (LTS)"

$failed = @()
foreach ($t in $BuildTargets) {
    try {
        switch -Regex ($t) {
            "^win-"   { Build-Windows -Arch ($t -replace "^win-", "") }
            "^linux-" { Build-Unix -Platform $t }
            "^osx-"   { Build-Unix -Platform $t }
        }
    } catch {
        Write-Host "`n  [FAIL] $t : $_" -ForegroundColor Red
        $failed += $t
    }
}

Write-Host ""
Write-Host "---------------------------------------------" -ForegroundColor DarkGray
if ($failed.Count -eq 0) {
    Write-Host "All builds succeeded.  Output: $OutputPath" -ForegroundColor Green
} else {
    Write-Host "Completed with failures: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
