# ================================================================
# Function: fncDemoTestTemplate
# Purpose : Developer reference template for building new tests
# Notes   :
#   - Demonstrates proper console output
#   - Demonstrates structured finding generation
#   - Shows deterministic ID usage
#   - Shows exploit/remediation narrative pattern
# ================================================================
function fncDemoTestTemplate {

    # ------------------------------------------------------------
    # SECTION 1: Standard Header Output
    #
    # Every test should:
    #   - Print a section header
    #   - Print what it is about to test
    #   - Be verbose enough for operators to understand intent
    # ------------------------------------------------------------
    fncPrintSectionHeader "Demo Developer Template Test"
    fncPrintMessage "Running demonstration logic for test developers..." "info"
    Write-Host ""

    # ------------------------------------------------------------
    # SECTION 2: Define Test ID
    #
    # IMPORTANT:
    #   This must match the JSON "Id" field exactly.
    #   It is used internally for mapping and enrichment.
    # ------------------------------------------------------------
    $testId = "DEMO-TEST-TEMPLATE"

    # ------------------------------------------------------------
    # SECTION 3: Example Test Logic
    #
    # Replace this with actual test logic.
    # Here we demonstrate:
    #   - Data collection
    #   - Console printing
    #   - Decision logic
    # ------------------------------------------------------------
    fncPrintMessage "Collecting example environment data..." "info"

    # Example: Check if running elevated
    $isElevated = $false
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    fncPrintMessage ("Running as Administrator: {0}" -f $isElevated) `
        ($(if ($isElevated) {"success"} else {"warning"}))

    Write-Host ""

    # ------------------------------------------------------------
    # SECTION 4: Build Exploitation Narrative
    #
    # IMPORTANT GUIDELINES:
    #   - Be clear.
    #   - Be realistic.
    #   - Focus on attacker tradecraft.
    # ------------------------------------------------------------
    $exploitationText = @"
This is a demonstration exploitation narrative.

When writing real tests:

- Describe how an attacker would realistically abuse the condition.
- Reference execution method (PowerShell, service abuse, DLL hijack, etc.).
- Explain impact (privilege escalation, persistence, lateral movement).
- Avoid generic statements like 'attacker can hack system'.

Example structure:
1. Precondition
2. Abuse method
3. Impact
4. Likely attacker objective
"@

    # ------------------------------------------------------------
    # SECTION 5: Build Remediation Narrative
    #
    # IMPORTANT GUIDELINES:
    #   - Provide actionable steps.
    #   - Prefer configuration changes over vague advice.
    #   - Mention GPO paths where appropriate.
    #   - Include monitoring guidance.
    # ------------------------------------------------------------
    $remediationText = @"
This is a demonstration remediation narrative.

When writing real remediation guidance:

- Provide exact configuration paths (GPO, registry, policy).
- Explain enforcement mechanisms (WDAC, AppLocker, ASR).
- Mention monitoring recommendations.
- Avoid vague 'harden system' advice.

Good remediation answers:
- Where to change
- What to set
- Why it matters
- What to monitor afterward
"@

    # ------------------------------------------------------------
    # SECTION 6: Decision Tree → Finding Creation
    #
    # IMPORTANT:
    #   - Always use fncAddFinding
    #   - Severity must align with actual risk
    #   - Status must reflect detection state
    #   - ID should be deterministic if data-based
    # ------------------------------------------------------------

    if (-not $isElevated) {

        fncPrintMessage "Demo condition triggered: Not running elevated." "warning"
        Write-Host ""

        fncAddFinding `
            -TestId $testId `
            -Id ("DEMO-" + (fncShortHashTag "NOT_ELEVATED")) `
            -Category "Demo Category" `
            -Title "Demo Condition: Non-Elevated Context" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "The script is not running with administrative privileges." `
            -Recommendation "Run with elevated permissions if required for full assessment coverage." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # SECTION 7: Positive / Hardened State
    #
    # IMPORTANT:
    #   Often Helpful to even produce a finding for secure states
    #   (Severity=Info, Status=Configured/Not Detected)
    # ------------------------------------------------------------
    fncPrintMessage "Demo secure state reached." "success"
    Write-Host ""

    fncAddFinding `
        -TestId $testId `
        -Id "DEMO-SECURE-STATE" `
        -Category "Demo Category" `
        -Title "Demo Condition: Secure State" `
        -Severity "Info" `
        -Status "Configured" `
        -Message "Demo condition evaluated successfully with no risk detected." `
        -Recommendation "No action required." `
        -Exploitation $exploitationText `
        -Remediation $remediationText

    Write-Host ""
}

Export-ModuleMember -Function fncDemoTestTemplate