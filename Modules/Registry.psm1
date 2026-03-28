# ================================================================
# Module  : Registry.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ================================================================
# Function: fncGetTestsRoot
# Purpose : Resolve the Tests directory from the current modules path
# Notes   : Expects modules\Registry.psm1 and sibling Tests\ folder
# ================================================================
function fncGetTestsRoot {

    try {

        if (-not (Get-Command -Name fncGetScriptDirectory -ErrorAction SilentlyContinue)) {
            return $null
        }

        $modulesRoot = fncGetScriptDirectory
        if ([string]::IsNullOrWhiteSpace($modulesRoot)) { return $null }

        $projectRoot = Split-Path -Path $modulesRoot -Parent
        if ([string]::IsNullOrWhiteSpace($projectRoot)) { return $null }

        $testsRoot = Join-Path $projectRoot "Tests"

        try { fncLog "DEBUG" ("Resolved Tests root: {0}" -f $testsRoot) } catch {}
        return $testsRoot
    }
    catch {
        try { fncLogException $_.Exception "fncGetTestsRoot" } catch {}
        return $null
    }
}

# ================================================================
# Function: fncGetPluginOSFromPath
# Purpose : Infer the target OS from folder structure
# Notes   : Example Tests\Defensive\Windows\* => Windows
# ================================================================
function fncGetPluginOSFromPath {
    param(
        [Parameter(Mandatory = $true)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$TestsRoot
    )

    try {
        $relative = $FolderPath.Substring($TestsRoot.Length).TrimStart('\', '/')
        $parts = @($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        foreach ($part in $parts) {
            switch -Regex ($part) {
                '^(Windows|Win)$' { return "Windows" }
                '^(Linux)$' { return "Linux" }
                '^(Mac|macOS|Darwin)$' { return "macOS" }
                '^(Cloud)$' { return "Cloud" }
                '^(Cross|Any|All)$' { return "Any" }
            }
        }

        return "Any"
    }
    catch {
        return "Any"
    }
}

# ================================================================
# Function: fncGetPluginStrategyFromPath
# Purpose : Infer the strategy (Offensive/Defensive) from folder structure
# Notes   : Example Tests\Defensive\* => Defensive
# ================================================================
function fncGetPluginStrategyFromPath {
    param(
        [Parameter(Mandatory = $true)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$TestsRoot
    )

    try {
        $relative = $FolderPath.Substring($TestsRoot.Length).TrimStart('\', '/')
        $parts = @($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        foreach ($part in $parts) {
            switch -Regex ($part) {
                '^Defensive$' { return "Defensive" }
                '^Offensive$' { return "Offensive" }
            }
        }

        return "Defensive"
    }
    catch {
        return "Defensive"
    }
}

# ================================================================
# Function: fncGetPluginScopeFromPath
# Purpose : Infer a default scope from folder structure
# Notes   : Example Tests\Windows\* => Workstation/Server/Domain
# ================================================================
function fncGetPluginScopeFromPath {
    param(
        [Parameter(Mandatory = $true)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$TestsRoot
    )

    try {
        $relative = $FolderPath.Substring($TestsRoot.Length).TrimStart('\', '/')
        $top = ($relative -split '[\\/]')[0]

        switch -Regex ($top) {
            '^(Windows|Win)$' { return @("Workstation", "Server", "Domain") }
            '^AD$' { return @("Domain") }
            '^(Cloud)$' { return @("Cloud") }
            '^Containers?$' { return @("Container") }
            '^Network$' { return @("Network") }
            '^Web(App)?$' { return @("WebApp") }
            '^DMZ$' { return @("DMZ") }
            '^SaaS$' { return @("SaaS") }
            default { return @("All") }
        }
    }
    catch {
        return @("All")
    }
}

# ================================================================
# Function: fncGetPluginCategoryFromPath
# Purpose : Infer a category from relative folder structure
# Notes   : Uses the second path element when available
# ================================================================
function fncGetPluginCategoryFromPath {
    param(
        [Parameter(Mandatory = $true)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$TestsRoot
    )

    try {
        $relative = $FolderPath.Substring($TestsRoot.Length).TrimStart('\', '/')
        $parts = @($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        if ($parts.Count -ge 2) { return $parts[1] }
        if ($parts.Count -ge 1) { return $parts[0] }
        return "Uncategorised"
    }
    catch {
        return "Uncategorised"
    }
}

# ================================================================
# Function: fncResolveScopes
# Purpose : Normalise scopes from manifest or inferred values
# Notes   : Returns All if Shared/All or no valid value present
# ================================================================
function fncResolveScopes {
    param([AllowNull()][object]$Scopes)

    if ($null -eq $Scopes) { return @("All") }

    $s = @()
    if ($Scopes -is [string]) { $s = @([string]$Scopes) }
    else { $s = @(fncSafeArray $Scopes) }

    $s = @(
        $s |
        ForEach-Object { fncSafeString $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ((fncSafeCount $s) -eq 0) { return @("All") }
    if ($s -contains "Shared" -or $s -contains "All") { return @("All") }

    return @($s)
}

# ================================================================
# Function: fncImportPluginScript
# Purpose : Import a plugin script from a test folder
# Notes   : Supports test.psm1 first, then test.ps1
# ================================================================
function fncImportPluginScript {
    param([Parameter(Mandatory = $true)][string]$FolderPath)

    $moduleFile = Get-ChildItem -LiteralPath $FolderPath -Filter "test.psm1" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $scriptFile = Get-ChildItem -LiteralPath $FolderPath -Filter "test.ps1"  -File -ErrorAction SilentlyContinue | Select-Object -First 1

    $target = $null
    if ($moduleFile) { $target = $moduleFile.FullName }
    elseif ($scriptFile) { $target = $scriptFile.FullName }

    if ([string]::IsNullOrWhiteSpace($target)) {
        try { fncLog "WARN" ("No test.psm1/test.ps1 found in: {0}" -f $FolderPath) } catch {}
        return $false
    }

    try {
        Import-Module -Name $target -Force -ErrorAction Stop | Out-Null
        try { fncLog "INFO" ("Imported plugin script: {0}" -f $target) } catch {}
        return $true
    }
    catch {
        try { fncLogException $_.Exception "fncImportPluginScript" } catch {}
        return $false
    }
}

# ================================================================
# Function: fncConvertManifestToTest
# Purpose : Convert manifest JSON into a normalised runtime test object
# Notes   : Falls back to folder structure when optional fields absent
# ================================================================
function fncConvertManifestToTest {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$TestsRoot
    )

    $id = fncSafeGetProp $Manifest "Id" ""
    $name = fncSafeGetProp $Manifest "Name" ""
    $function = fncSafeGetProp $Manifest "Function" ""

    if ([string]::IsNullOrWhiteSpace($id)) { throw "Manifest missing Id: $FolderPath" }
    if ([string]::IsNullOrWhiteSpace($name)) { throw "Manifest missing Name: $FolderPath" }
    if ([string]::IsNullOrWhiteSpace($function)) { throw "Manifest missing Function: $FolderPath" }

    $category = fncSafeGetProp $Manifest "Category" $null
    if ($null -eq $category -or [string]::IsNullOrWhiteSpace((fncSafeString $category))) {
        $category = fncGetPluginCategoryFromPath -FolderPath $FolderPath -TestsRoot $TestsRoot
    }

    $scopes = fncSafeGetProp $Manifest "Scopes" $null
    if ($null -eq $scopes) {
        $scopes = fncGetPluginScopeFromPath -FolderPath $FolderPath -TestsRoot $TestsRoot
    }
    $scopes = fncResolveScopes $scopes

    $os = fncSafeString (fncSafeGetProp $Manifest "OS" "")
    if ([string]::IsNullOrWhiteSpace($os)) {
        $os = fncGetPluginOSFromPath -FolderPath $FolderPath -TestsRoot $TestsRoot
    }

    $strategy = fncSafeString (fncSafeGetProp $Manifest "Strategy" "")
    if ([string]::IsNullOrWhiteSpace($strategy)) {
        $strategy = fncGetPluginStrategyFromPath -FolderPath $FolderPath -TestsRoot $TestsRoot
    }

    return [pscustomobject]@{
        SchemaVersion = [int](fncSafeGetProp $Manifest "SchemaVersion" 1)
        Id            = $id
        Name          = $name
        Function      = $function
        Category      = $category
        Scopes        = @($scopes)
        Enabled       = [bool](fncSafeGetProp $Manifest "Enabled" $true)
        RequiresAdmin = [bool](fncSafeGetProp $Manifest "RequiresAdmin" $false)
        Description   = fncSafeString (fncSafeGetProp $Manifest "Description" "")
        WIP           = [bool](fncSafeGetProp $Manifest "WIP" $false)
        Mappings      = $null
        References    = fncSafeGetProp $Manifest "References" $null
        Path          = $FolderPath
        Maturity      = fncSafeGetProp $Manifest "Maturity" "Experimental"
        Risk          = fncSafeGetProp $Manifest "Risk" "Low"
        OS            = $os
        Strategy      = $strategy
    }
}

# ================================================================
# Function: fncRegisterDiscoveredTest
# Purpose : Add a single test object to ProberState (dynamic / reload use)
# Notes   : For bulk initial load use fncDiscoverTests which assigns once
# ================================================================
function fncRegisterDiscoveredTest {
    param([Parameter(Mandatory = $true)]$Test)

    if ($null -eq $global:ProberState.Tests) {
        $global:ProberState.Tests = @()
    }

    # Use a hashtable for O(1) duplicate check rather than a Where-Object scan
    if (-not ($global:ProberState.PSObject.Properties.Name -contains "_TestIdSet")) {
        $global:ProberState | Add-Member -NotePropertyName "_TestIdSet" -NotePropertyValue @{}
    }

    $id = fncSafeString $Test.Id

    if ($global:ProberState._TestIdSet.ContainsKey($id)) {
        # Replace existing entry (reload scenario)
        $global:ProberState.Tests = @($global:ProberState.Tests | Where-Object { (fncSafeString $_.Id) -ne $id })
    }

    $global:ProberState.Tests += $Test
    $global:ProberState._TestIdSet[$id] = $true

    if (-not ($global:ProberState.PSObject.Properties.Name -contains "_LoadedTestIds")) {
        $global:ProberState | Add-Member -NotePropertyName "_LoadedTestIds" -NotePropertyValue @()
    }

    if ($global:ProberState._LoadedTestIds -notcontains $id) {
        $global:ProberState._LoadedTestIds += $id
    }
}

# ================================================================
# Function: fncDiscoverTests
# Purpose : Discover all tests from filesystem manifests
# Notes   : Tests\Windows\*, Tests\AD\*, Tests\Cloud\*, etc
# ================================================================
function fncDiscoverTests {

    $loadedCount  = 0
    $skippedCount = 0
    $failedCount  = 0
    $batch        = [System.Collections.Generic.List[object]]::new()

    $testsRoot = fncGetTestsRoot
    if ([string]::IsNullOrWhiteSpace($testsRoot) -or -not (Test-Path -LiteralPath $testsRoot)) {
        try { fncPrintMessage ("Tests directory not found: {0}" -f (fncSafeString $testsRoot)) "warning" } catch {}
        return
    }

    # Detect current OS once - avoid per-test calls
    $_currentOS = "Windows"
    try {
        if (Get-Command fncGetCurrentOS -ErrorAction SilentlyContinue) {
            $_currentOS = fncGetCurrentOS
        }
        elseif (Get-Variable IsLinux -ErrorAction SilentlyContinue) {
            if ($IsLinux)  { $_currentOS = "Linux" }
            elseif ($IsMacOS) { $_currentOS = "macOS" }
        }
    }
    catch {}

    try { fncLog "INFO" ("Starting plugin discovery from: {0} (OS: {1})" -f $testsRoot, $_currentOS) } catch {}

    $manifestFiles = Get-ChildItem -LiteralPath $testsRoot -Filter "test.json" -File -Recurse -ErrorAction SilentlyContinue

    foreach ($manifestFile in (fncSafeArray $manifestFiles)) {

        $folder   = $manifestFile.Directory.FullName
        $manifest = $null

        try {
            $manifest = fncReadJsonFileSafe $manifestFile.FullName $null

            if ($null -eq $manifest) {
                $failedCount++
                fncLog "WARN" ("Invalid or empty manifest skipped: {0}" -f $manifestFile.FullName)
                continue
            }
        }
        catch {
            $failedCount++
            try { fncPrintMessage ("Invalid manifest: {0}" -f $manifestFile.FullName) "error" } catch {}
            try { fncLogException $_.Exception "fncDiscoverTests manifest parse" } catch {}
            continue
        }

        try {
            $test = fncConvertManifestToTest -Manifest $manifest -FolderPath $folder -TestsRoot $testsRoot
        }
        catch {
            $failedCount++
            try { fncPrintMessage $_.Exception.Message "error" } catch {}
            continue
        }

        # Skip tests whose OS doesn't match the current platform - avoids
        # importing irrelevant modules (e.g. Linux tests on Windows) which
        # is the primary startup cost when many test plugins are present.
        $testOS = fncSafeString $test.OS
        if ($testOS -ne "Any" -and $testOS -ne "" -and $testOS -ne $_currentOS) {
            $skippedCount++
            try { fncLog "DEBUG" ("Skipping OS-mismatched test [{0}]: {1}" -f $testOS, $test.Id) } catch {}
            continue
        }

        if (-not (fncImportPluginScript -FolderPath $folder)) {
            $failedCount++
            try { fncPrintMessage ("Plugin import failed: {0}" -f $test.Name) "warning" } catch {}
            continue
        }

        # Load mappings from psm1 function now that the module is imported
        $mappingsFn = "fncGetMappings_{0}" -f ($test.Id -replace '-', '_')
        if (Get-Command $mappingsFn -ErrorAction SilentlyContinue) {
            try { $test.Mappings = & $mappingsFn } catch {}
        }

        if (-not (Get-Command -Name $test.Function -ErrorAction SilentlyContinue)) {
            $failedCount++
            try { fncPrintMessage ("Function not found after import: {0}" -f $test.Function) "error" } catch {}
            continue
        }

        $batch.Add($test)
        $loadedCount++

        try {
            if ($global:ProberState.Config.DEBUG) {
                fncPrintMessage ("Loaded Test: {0}" -f $test.Name) "debug"
            }
        }
        catch {}
    }

    # Bulk-assign to avoid O(n²) array appends inside the loop
    if ($batch.Count -gt 0) {
        $global:ProberState.Tests = $batch.ToArray()

        if (-not ($global:ProberState.PSObject.Properties.Name -contains "_TestIdSet")) {
            $global:ProberState | Add-Member -NotePropertyName "_TestIdSet" -NotePropertyValue @{}
        }
        if (-not ($global:ProberState.PSObject.Properties.Name -contains "_LoadedTestIds")) {
            $global:ProberState | Add-Member -NotePropertyName "_LoadedTestIds" -NotePropertyValue @()
        }
        foreach ($t in $batch) {
            $tid = fncSafeString $t.Id
            $global:ProberState._TestIdSet[$tid] = $true
            if ($global:ProberState._LoadedTestIds -notcontains $tid) {
                $global:ProberState._LoadedTestIds += $tid
            }
        }
    }

    try {
        fncLog "INFO" ("Plugin discovery complete. Loaded={0}, Skipped(OS)={1}, Failed={2}" -f $loadedCount, $skippedCount, $failedCount)
    }
    catch {}
}

# ================================================================
# Function: fncRegisterTests
# Purpose : Build the in-memory test registry from discovered plugins
# Notes   : Leaves a NOOP fallback if no tests are found
# ================================================================
function fncRegisterTests {

    if ($null -eq $global:ProberState) {
        throw "ProberState is not initialised."
    }

    $global:ProberState.Tests = @()
    fncDiscoverTests

    if ((fncSafeCount $global:ProberState.Tests) -eq 0) {

        function fncNoOpTest {
            try { fncPrintMessage "No tests discovered." "warning" } catch { Write-Host "No tests discovered." }
        }

        $global:ProberState.Tests += [pscustomobject]@{
            SchemaVersion = 6
            Id            = "NOOP"
            Name          = "No tests discovered"
            Function      = "fncNoOpTest"
            Category      = "Utilities"
            Scopes        = @("All")
            Enabled       = $true
            RequiresAdmin = $false
            Description   = "Fallback placeholder"
            WIP           = $false
            Mappings      = $null
            References    = $null
            Path          = ""
            OS            = "Any"
            Strategy      = "Defensive"
        }
    }

    try {
        fncLog "INFO" ("Registered tests: {0}" -f (fncSafeCount $global:ProberState.Tests))
    }
    catch {}
}

# ================================================================
# Function: fncGetUniqueCategories
# Purpose : Return unique primary categories for current scope
# Notes   : Works with string or structured category objects
# ================================================================
function fncGetActiveStrategy {
    try {
        $s = fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")
        if ($s -eq "blue") { return "Defensive" }
        return "All"
    }
    catch { return "All" }
}

function fncGetUniqueCategories {
    param(
        [ValidateSet('All', 'Workstation', 'Server', 'Domain', 'DMZ', 'Cloud', 'SaaS', 'Container', 'Network', 'WebApp', 'Entra', 'Azure', 'AWS')]
        [string]$Scope = "All"
    )

    $tests = fncSafeArray $global:ProberState.Tests
    if ((fncSafeCount $tests) -eq 0) { return @() }

    $activeStrategy = fncGetActiveStrategy

    $cats = @(
        $tests |
        Where-Object {
            $_ -and $_.Enabled -eq $true -and
            ($activeStrategy -eq "All" -or (fncSafeString $_.Strategy) -eq $activeStrategy) -and
            (
                $Scope -eq "All" -or
                @(fncSafeArray $_.Scopes) -contains "All" -or
                @(fncSafeArray $_.Scopes) -contains $Scope
            )
        } |
        ForEach-Object {
            $catObj = $_.Category
            if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {
                fncSafeString $catObj.Primary
            }
            else {
                fncSafeString $catObj
            }
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )

    return @($cats)
}

# ================================================================
# Function: fncGetTestsByScope
# Purpose : Return tests filtered by scope/category
# Notes   : Uses inferred or manifest-provided scopes
# ================================================================
function fncGetTestsByScope {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Workstation', 'Server', 'Domain', 'DMZ', 'Cloud', 'SaaS', 'Container', 'Network', 'WebApp', 'Entra', 'Azure', 'AWS')]
        [string]$Scope,

        [string]$Category = "",

        [switch]$IncludeDisabled
    )

    $tests = fncSafeArray $global:ProberState.Tests
    if ((fncSafeCount $tests) -eq 0) { return @() }

    if (-not $IncludeDisabled) {
        $tests = @($tests | Where-Object { $_ -and $_.Enabled -eq $true })
    }

    $activeStrategy = fncGetActiveStrategy
    if ($activeStrategy -ne "All") {
        $tests = @($tests | Where-Object { $_ -and (fncSafeString $_.Strategy) -eq $activeStrategy })
    }

    if ($Scope -ne "All") {
        $tests = @(
            $tests | Where-Object {
                $_ -and $_.Scopes -and (
                    @(fncSafeArray $_.Scopes) -contains "All" -or
                    @(fncSafeArray $_.Scopes) -contains $Scope
                )
            }
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($Category)) {
        $tests = @(
            $tests | Where-Object {
                $catObj = $_.Category
                if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {
                    (fncSafeString $catObj.Primary) -eq (fncSafeString $Category)
                }
                else {
                    (fncSafeString $catObj) -eq (fncSafeString $Category)
                }
            }
        )
    }

    return @($tests)
}

# ================================================================
# Function: fncExecTestCmd  (module-level private)
# Purpose : Executes a single test command with error handling
# Notes   : Extracted from fncInvokeTestById to avoid per-call redefinition
# ================================================================
function fncExecTestCmd {
    param(
        [string]$ModeLabel,
        $Test,
        $Command,
        [string]$TestId
    )

    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = "Stop"

    try {
        fncPrintMessage ("{0}: {1}" -f $ModeLabel, (fncSafeString $Test.Name)) "info"
        & $Command -ErrorAction Stop
        fncPrintMessage ("Completed [{0}]: {1}" -f $ModeLabel, (fncSafeString $Test.Name)) "success"
    }
    catch {
        fncPrintMessage ("Test execution failed: {0}" -f $_.Exception.Message) "error"

        fncLog "ERROR" "===== TEST FAILURE ====="
        fncLog "ERROR" ("Test Id   : {0}" -f $TestId)
        fncLog "ERROR" ("Test Name : {0}" -f (fncSafeString $Test.Name))
        fncLog "ERROR" ("Mode      : {0}" -f $ModeLabel)
        fncLog "ERROR" ("Message   : {0}" -f $_.Exception.Message)

        if ($_.InvocationInfo) {
            fncLog "ERROR" ("Script : {0}" -f $_.InvocationInfo.ScriptName)
            fncLog "ERROR" ("Line   : {0}" -f $_.InvocationInfo.ScriptLineNumber)
            fncLog "ERROR" ("Code   : {0}" -f $_.InvocationInfo.Line.Trim())
        }

        if ($_.ScriptStackTrace) {
            fncLog "ERROR" $_.ScriptStackTrace
        }
    }
    finally {
        $ErrorActionPreference = $oldPref
    }
}

# ================================================================
# Function: fncInvokeTestById
# Purpose : Execute a discovered plugin test by Id
# Notes   : Preserves admin enforcement and logging
# ================================================================
function fncInvokeTestById {

    param([Parameter(Mandatory = $true)][string]$TestId)

    $id = $TestId

    # Ensure execution history exists
    if (-not $global:ProberState.ExecutionHistory) {
        $global:ProberState.ExecutionHistory = @{}
    }

    if (-not $global:ProberState.ExecutionHistory.ContainsKey($id)) {

        $global:ProberState.ExecutionHistory[$id] = @{
            RunCount = 0
        }
    }

    $entry = $global:ProberState.ExecutionHistory[$id]

    $entry.RunCount++
    $entry.LastRun = Get-Date
    # History is flushed once per session in fncMain's finally block

    $tests = fncSafeArray $global:ProberState.Tests
    $t = @($tests | Where-Object { (fncSafeString $_.Id) -eq (fncSafeString $TestId) }) | Select-Object -First 1


    if ($null -eq $t) {
        fncPrintMessage ("Unknown test id: {0}" -f $TestId) "warning"
        return
    }


    $needsAdmin = [bool](fncSafeGetProp $t "RequiresAdmin" $false)

    if ($needsAdmin -and -not (fncIsAdmin)) {
        fncPrintMessage ("Test requires Administrator: {0}" -f (fncSafeString $t.Name)) "warning"
        return
    }


    $fn = fncSafeString (fncSafeGetProp $t "Function" "")

    if ([string]::IsNullOrWhiteSpace($fn)) {
        fncPrintMessage ("Test has no function mapped: {0}" -f (fncSafeString $t.Name)) "warning"
        return
    }


    $cmd = Get-Command $fn -ErrorAction SilentlyContinue

    if (-not $cmd) {
        fncPrintMessage ("Mapped function not found: {0}" -f $fn) "warning"
        return
    }


    $operatorStrategy = fncSafeString (fncSafeGetProp $global:ProberState.Config "Strategy" "red")

    fncExecTestCmd -ModeLabel $operatorStrategy -Test $t -Command $cmd -TestId $id
}

# ================================================================
# Function: fncRescanTestModules
# Purpose : Reload all test plugins at runtime without restarting
# ================================================================
function fncRescanTestModules {

    try { fncTestMessage "Reloading test modules..." "link" } catch { Write-Host "Reloading test modules..." }

    $before = (fncSafeCount $global:ProberState.Tests)

    fncRegisterTests

    $after = (fncSafeCount $global:ProberState.Tests)

    try {
        fncTestMessage ("Reload complete. Tests loaded: {0} (was {1})" -f $after, $before) "link"
    }
    catch {
        Write-Host ("Reload complete. Tests loaded: {0} (was {1})" -f $after, $before)
    }
}

Export-ModuleMember -Function @(
    "fncRegisterTests",
    "fncDiscoverTests",
    "fncGetUniqueCategories",
    "fncGetTestsByScope",
    "fncInvokeTestById",
    "fncGetTestsRoot",
    "fncRescanTestModules",
    "fncGetActiveStrategy"
)