# ================================================================
# Module  : UI.Framework.psm1
# ================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncGetRegistryStats {

    $tests = @()

    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            $tests = fncSafeArray $global:ProberState.Tests
        }
    }
    catch {}

    return [pscustomobject]@{
        TotalRegistered = fncSafeCount $tests
    }
}

function fncGetModuleLoadSummary {

    $modules = @()

    try {
        $modules = @(Get-Module -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like "UI.*" -or $_.Name -like "*Prober*"
            })
    }
    catch {}

    $names = @($modules | Select-Object -ExpandProperty Name -Unique -ErrorAction SilentlyContinue)

    return [pscustomobject]@{
        UniqueModules = fncSafeCount $names
    }
}

Export-ModuleMember -Function @(
    "fncGetRegistryStats",
    "fncGetModuleLoadSummary"
)
