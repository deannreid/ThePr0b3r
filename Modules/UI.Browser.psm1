# ================================================================
# Module  : UI.Browser.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncRunTestList {

    param(
        [Parameter(Mandatory = $true)][object[]]$Tests,
        [string]$Label = "tests"
    )

    $count = fncSafeCount $Tests
    if ($count -eq 0) {
        fncSafePrintMessage "No tests to run." "warning"
        fncSafePause
        return
    }

    fncPrintMessage ("Starting: {0} {1}" -f $count, $Label) "info"
    Write-Host ""

    $i = 0
    foreach ($t in (fncSafeArray $Tests)) {
        $i++
        fncPrintMessage ("[{0}/{1}] {2}" -f $i, $count, (fncSafeString $t.Name)) "info"
        fncSafeInvokeTestById (fncSafeString $t.Id)
        Write-Host ""
    }

    Write-Host ""
    fncPrintMessage ("Run complete - {0} {1} executed." -f $count, $Label) "proten"

    # Post-run findings summary
    try {
        if (fncCommandExists "fncPrintFindingsSummary") { fncPrintFindingsSummary }
    }
    catch {}

    fncSafePause
}

function fncShowRunAllMenu {

    $all = @(fncSafeArray $global:ProberState.Tests | Where-Object { $_ -and $_.Enabled -eq $true })
    $offensive = @($all | Where-Object { (fncSafeString $_.Strategy) -eq "Offensive" })
    $defensive = @($all | Where-Object { (fncSafeString $_.Strategy) -eq "Defensive" })

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Run All Tests"
        fncSafeDivider

        fncRenderMenuOption "1" ("Run All Offensive Tests  ({0})" -f (fncSafeCount $offensive))
        fncRenderMenuOption "2" ("Run All Defensive Tests  ({0})" -f (fncSafeCount $defensive))
        fncRenderMenuOption "3" ("Run All Tests            ({0})" -f (fncSafeCount $all))

        Write-Host ""
        fncRenderMenuOption "B" "Back"
        fncRenderMenuOption "Q" "Quit"
        Write-Host ""

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "1" { fncRunTestList -Tests $offensive -Label "offensive tests" }
            "2" { fncRunTestList -Tests $defensive -Label "defensive tests" }
            "3" { fncRunTestList -Tests $all       -Label "tests" }
            "B" { return }
            "Q" { return "QUIT" }
            default { fncSafePrintMessage "Invalid selection." "warning" }
        }
    }
}

function fncGetAllTestsSafe {
    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            return @(fncSafeArray $global:ProberState.Tests)
        }
    }
    catch {}
    return @()
}

function fncSafeInvokeTestById {
    param([string]$Id)

    if (fncCommandExists "fncInvokeTestById") {
        fncInvokeTestById -TestId $Id
        return
    }

    fncSafePrintMessage ("Invoke missing: fncInvokeTestById (wanted {0})" -f $Id) "warning"
}

function fncSafeEnvLine {

    if (fncCommandExists "fncRenderEnvironmentLine") {
        fncRenderEnvironmentLine
        return
    }

    $p = "Unknown"
    try { $p = fncSafeString $global:ProberState.EnvProfile } catch {}
    Write-Host ("EnvProfile: {0}" -f $p)
}

function fncSafeFindingsSummary {
    if (fncCommandExists "fncPrintFindingsSummary") {
        fncPrintFindingsSummary
    }
}

function fncSafeRenderTestEntry {

    param(
        [int]$Index,
        [object]$Test
    )

    if (fncCommandExists "fncRenderTestEntry") {
        fncRenderTestEntry -Index $Index -Test $Test
        return
    }

    Write-Host ("[{0}] {1}" -f $Index, (fncSafeString $Test.Name))
}

function fncShowTestsForCategory {

    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [ValidateSet('All', 'Workstation', 'Server', 'Domain', 'DMZ', 'Cloud', 'SaaS', 'Container', 'Network', 'WebApp', 'Entra', 'Azure', 'AWS')]
        [string]$Scope = "All"
    )

    if (-not (fncCommandExists "fncGetTestsByScope")) {
        fncSafePrintMessage "Missing required function: fncGetTestsByScope" "error"
        fncSafePause
        return
    }

    $tests = @()

    try {
        $tests = @(fncSafeArray (fncGetTestsByScope -Scope $Scope -Category $Category))
    }
    catch {
        fncSafePrintMessage ("Failed retrieving tests: {0}" -f $_.Exception.Message) "error"
        fncSafePause
        return
    }

    if ((fncSafeCount $tests) -eq 0) {
        fncSafePrintMessage "No tests in this category." "warning"
        fncSafePause
        return
    }

    $currentOS = "Windows"
    try {
        if (fncCommandExists "fncGetCurrentOS") { $currentOS = fncGetCurrentOS }
    }
    catch {}

    while ($true) {

        fncSafeRenderHeader
        fncPrintKey
        fncSafeFindingsSummary
        fncPrintMessage "  " "plain"
        fncSafeEnvLine
        fncSafeSectionHeader (fncSafeString $Category)
        fncWriteColour "ID   TEST NAME                                               MATURITY      RISK      OS         STRATEGY    " Cyan
        fncWriteColour "-----------------------------------------------------------------------------------------------------------" DarkGray

        $indexMap = @()
        $unavailableList = @()
        $domainUnavailList = @()
        $entraUnavailList = @()
        $azureUnavailList = @()
        $awsUnavailList = @()



        $i = 1

        $adIsConnected = (fncCommandExists "fncADIsConnected") -and (fncADIsConnected)
        $entraIsConnected = (fncCommandExists "fncEntraIsConnected") -and (fncEntraIsConnected)
        $azureIsConnected = (fncCommandExists "fncAzureIsConnected") -and (fncAzureIsConnected)
        $awsIsConnected = (fncCommandExists "fncAWSIsConnected") -and (fncAWSIsConnected)

        foreach ($t in $tests) {

            $testOS = fncSafeString (fncSafeGetProp $t "OS" "Any")
            $testScopes = @(fncSafeArray (fncSafeGetProp $t "Scopes" @()))
            $isDomainTest = $testScopes -contains "Domain"
            $isEntraTest = $testScopes -contains "Entra"
            $isAzureTest = $testScopes -contains "Azure"
            $isAWSTest = $testScopes -contains "AWS"

            $isOSAvail = ($testOS -eq "Any" -or $testOS -eq $currentOS)
            $isDomainAvail = (-not $isDomainTest) -or $adIsConnected
            $isEntraAvail = (-not $isEntraTest) -or $entraIsConnected
            $isAzureAvail = (-not $isAzureTest) -or $azureIsConnected
            $isAWSAvail = (-not $isAWSTest) -or $awsIsConnected

            if ($isOSAvail -and $isDomainAvail -and $isEntraAvail -and $isAzureAvail -and $isAWSAvail) {

                fncRenderTestEntry -Index $i -Test $t
                $indexMap += $t
                $i++
            }
            elseif (-not $isDomainAvail) {
                $domainUnavailList += $t
            }
            elseif (-not $isEntraAvail) {
                $entraUnavailList += $t
            }
            elseif (-not $isAzureAvail) {
                $azureUnavailList += $t
            }
            elseif (-not $isAWSAvail) {
                $awsUnavailList += $t
            }
            else {
                $unavailableList += $t
            }
        }

        if ((fncSafeCount $domainUnavailList) -gt 0) {
            Write-Host ""
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour "---- Domain Connection Required (AD not connected) ----" DarkGray
            }
            else {
                Write-Host "---- Domain Connection Required (AD not connected) ----"
            }
            Write-Host ""
            foreach ($t in $domainUnavailList) {
                fncRenderTestEntry -Index 0 -Test $t -Unavailable $true
            }
        }

        if ((fncSafeCount $entraUnavailList) -gt 0) {
            Write-Host ""
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour "---- Entra Connection Required (Entra not connected) ----" DarkGray
            }
            else {
                Write-Host "---- Entra Connection Required (Entra not connected) ----"
            }
            Write-Host ""
            foreach ($t in $entraUnavailList) {
                fncRenderTestEntry -Index 0 -Test $t -Unavailable $true
            }
        }

        if ((fncSafeCount $azureUnavailList) -gt 0) {
            Write-Host ""
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour "---- Azure Connection Required (Azure not connected) ----" DarkGray
            }
            else {
                Write-Host "---- Azure Connection Required (Azure not connected) ----"
            }
            Write-Host ""
            foreach ($t in $azureUnavailList) {
                fncRenderTestEntry -Index 0 -Test $t -Unavailable $true
            }
        }

        if ((fncSafeCount $awsUnavailList) -gt 0) {
            Write-Host ""
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour "---- AWS Connection Required (AWS not connected) ----" DarkGray
            }
            else {
                Write-Host "---- AWS Connection Required (AWS not connected) ----"
            }
            Write-Host ""
            foreach ($t in $awsUnavailList) {
                fncRenderTestEntry -Index 0 -Test $t -Unavailable $true
            }
        }

        if ((fncSafeCount $unavailableList) -gt 0) {
            Write-Host ""
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour "---- Not Available on this OS ----" DarkGray
            }
            else {
                Write-Host "---- Not Available on this OS ----"
            }
            Write-Host ""
            foreach ($t in $unavailableList) {
                fncRenderTestEntry -Index 0 -Test $t -Unavailable $true
            }
        }

        Write-Host ""

        if (fncCommandExists "fncRenderMenuOption") {

            fncRenderMenuOption "A" ("Run All Tests in Category  ({0})" -f (fncSafeCount $indexMap))
            fncRenderMenuOption "B" "Back"
            fncRenderMenuOption "Q" "Quit"

        }
        else {

            fncSafeBackQuit
        }

        Write-Host ""

        $choice = Read-Host "Select test"

        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "A" { fncRunTestList -Tests $indexMap -Label ("tests in {0}" -f $Category) }

            "B" { return }

            "Q" { return "QUIT" }

            default {

                if ($choice -match '^\d+$') {

                    $index = [int]$choice

                    if ($index -ge 1 -and $index -le (fncSafeCount $indexMap)) {

                        $picked = $indexMap[$index - 1]
                        $id = fncSafeString $picked.Id

                        if (-not [string]::IsNullOrWhiteSpace($id)) {

                            fncSafeInvokeTestById $id

                            fncSafePause
                        }
                    }
                }
            }
        }
    }
}

function fncShowCategoryMenu {

    param(
        [ValidateSet('All', 'Workstation', 'Server', 'Domain', 'DMZ', 'Cloud', 'SaaS', 'Container', 'Network', 'WebApp', 'Entra', 'Azure', 'AWS')]
        [string]$Scope = "All"
    )

    $cats = @()

    if (fncCommandExists "fncGetUniqueCategories") {
        try { $cats = @(fncSafeArray (fncGetUniqueCategories -Scope $Scope)) } catch { $cats = @() }
    }

    if ((fncSafeCount $cats) -eq 0) {

        $tests = fncGetAllTestsSafe

        $cats = @(
            $tests |
            Where-Object {
                $_.Enabled -eq $true -and
                (
                    $Scope -eq "All" -or
                    $_.Scopes -contains "All" -or
                    @(fncSafeArray $_.Scopes) -contains $Scope
                )
            } |
            ForEach-Object {
                $catObj = $_.Category
                $c = if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {
                    fncSafeString $catObj.Primary
                } else {
                    fncSafeString $catObj
                }
                if ([string]::IsNullOrWhiteSpace($c)) { "Uncategorised" } else { $c }
            } |
            Sort-Object -Unique
        )
        
    }

    $cats = @($cats | ForEach-Object { fncSafeString $_ })

    if ((fncSafeCount $cats) -eq 0) {
        fncSafePrintMessage "No categories loaded." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Test Categories"
        fncSafeEnvLine
        fncSafeFindingsSummary
        fncSafeDivider

        for ($i = 0; $i -lt (fncSafeCount $cats); $i++) {
            fncSafeMenuOption (fncSafeString ($i + 1)) (fncSafeString $cats[$i])
        }

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select category"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "B" { return }
            "Q" { return "QUIT" }

            default {
                if ($choice -match '^\d+$') {

                    $index = [int]$choice - 1

                    if ($index -ge 0 -and $index -lt (fncSafeCount $cats)) {

                        $r = fncShowTestsForCategory `
                            -Category (fncSafeString $cats[$index]) `
                            -Scope $Scope

                        if ($r -eq "QUIT") { return "QUIT" }
                    }
                }
            }
        }
    }
}

function fncSelectEnvironmentScope {

    while ($true) {

        Write-Host ""
        Write-Host "Select Environment Scope:"
        Write-Host ""
        Write-Host "[1] DMZ"
        Write-Host "[2] Workstation"
        Write-Host "[3] Server"
        Write-Host "[4] Domain"
        Write-Host "[5] Cloud"
        Write-Host "[6] SaaS"
        Write-Host "[7] Container"
        Write-Host "[8] Network"
        Write-Host "[9] WebApp"
        Write-Host "[A] All"
        Write-Host "[Q] Back"
        Write-Host ""

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {
            "1" { return "DMZ" }
            "2" { return "Workstation" }
            "3" { return "Server" }
            "4" { return "Domain" }
            "5" { return "Cloud" }
            "6" { return "SaaS" }
            "7" { return "Container" }
            "8" { return "Network" }
            "9" { return "WebApp" }
            "A" { return "All" }
            "Q" { return $null }
            default { fncSafePrintMessage "Invalid selection." "warning" }
        }
    }
}

function fncSearchAndRunTest {

    $search = Read-Host "Enter test name or ID"
    if ([string]::IsNullOrWhiteSpace($search)) { return }

    $all = fncGetAllTestsSafe

    $tests = @(
        $all | Where-Object {
            (fncSafeString $_.Name -like "*$search*") -or
            (fncSafeString $_.Id   -like "*$search*")
        }
    )

    if ((fncSafeCount $tests) -eq 0) {
        fncSafePrintMessage "No matching tests found." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Search Results"
        fncSafeDivider

        for ($i = 0; $i -lt (fncSafeCount $tests); $i++) {
            fncSafeRenderTestEntry ($i + 1) $tests[$i]
        }

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select test"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        if ($choice.ToUpper() -eq "B") { return }
        if ($choice.ToUpper() -eq "Q") { return }

        if ($choice -match '^\d+$') {

            $index = [int]$choice - 1

            if ($index -ge 0 -and $index -lt (fncSafeCount $tests)) {

                $id = fncSafeString $tests[$index].Id

                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    fncSafeInvokeTestById $id
                    fncSafePause
                }
            }
        }
    }
}

Export-ModuleMember -Function @(
    "fncShowCategoryMenu",
    "fncShowTestsForCategory",
    "fncShowRunAllMenu",
    "fncRunTestList",
    "fncSearchAndRunTest",
    "fncSelectEnvironmentScope"
)
