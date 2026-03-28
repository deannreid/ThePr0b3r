# Test Authoring Guide

This guide covers everything needed to create a custom test plugin for THE Pr0b3r.

Each test is a self-contained folder containing exactly two files:

| File | Purpose |
|------|---------|
| `test.json` | Manifest - metadata, categorisation, scopes |
| `test.psm1` | Implementation - framework mappings and test logic |

---

## Table of Contents

1. [Folder Structure](#1-folder-structure)
2. [Naming Conventions](#2-naming-conventions)
3. [test.json Schema](#3-testjson-schema)
4. [test.psm1 Structure](#4-testpsm1-structure)
5. [Submitting Findings](#5-submitting-findings)
6. [Helper Functions Reference](#6-helper-functions-reference)
7. [Framework Mappings](#7-framework-mappings)
8. [Complete Example](#8-complete-example)
9. [Checklist](#9-checklist)

---

## 1. Folder Structure

Tests live under the `Tests\` directory. The folder path determines how the framework categorises the test. Place your test in the correct subtree:

```
Tests\
  Defensive\          <- blue strategy
    Windows\          <- target OS
      <Category>\     <- category name (used in menus)
        <TEST-ID>\    <- unique test identifier
          test.json
          test.psm1
```

**Example:**

```
Tests\Defensive\Windows\LoggingMonitoring\SYSMON-INSTALL-CHECK\
  test.json
  test.psm1
```

### OS folders

| Folder | Inferred OS |
|--------|-------------|
| `Windows` | Windows |
| `Linux` | Linux |

### Strategy folders

| Folder | Strategy |
|--------|---------|
| `Defensive` | Blue team / control validation |
| `Offensive` | Red team / attack surface (not in public release) |

Strategy and OS can always be overridden explicitly in `test.json` if needed.

---

## 2. Naming Conventions

**Test ID** (`TEST-ID` folder name and `"Id"` in `test.json`)

- All uppercase
- Words separated by hyphens
- Descriptive and unique across the entire test library
- Should reflect what is being checked, not what is being attacked

```
SYSMON-INSTALL-CHECK
WEF-CONFIG-CHECK
APPLOCKER-POLICY-CHECK
LAPS-DEPLOYMENT-CHECK
```

**Function name** (`"Function"` in `test.json` and the PowerShell function name in `test.psm1`)

- Camel case with `fnc` prefix
- Prefix `fncCheck` for test functions
- Must be globally unique

```
fncCheckSysmonInstallStatus
fncCheckWEFConfiguration
fncCheckAppLockerPolicy
```

**Mappings getter function** (in `test.psm1`)

Follow the pattern exactly - the framework calls this automatically:

```
fncGetMappings_<TEST_ID_WITH_HYPHENS_REPLACED_BY_UNDERSCORES>
```

```powershell
# For test ID: SYSMON-INSTALL-CHECK
function fncGetMappings_SYSMON_INSTALL_CHECK { return $script:Mappings }
```

---

## 3. test.json Schema

```json
{
    "SchemaVersion": 6,
    "Id":            "SYSMON-INSTALL-CHECK",
    "Name":          "Sysmon Installation Validation",
    "Function":      "fncCheckSysmonInstallStatus",
    "Category": {
        "Primary":       "Logging Monitoring",
        "Subcategories": ["Endpoint Telemetry", "Process Monitoring"]
    },
    "Scopes":        ["Workstation", "Server"],
    "RequiresAdmin": true,
    "Enabled":       true,
    "Maturity":      "Stable",
    "Risk":          "Low",
    "Description":   "Checks whether Sysmon is installed and running as a service.",
    "OS":            "Windows",
    "Strategy":      "Defensive"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `SchemaVersion` | int | Yes | Always `6` |
| `Id` | string | Yes | Unique test identifier. Must match the folder name. |
| `Name` | string | Yes | Human-readable display name shown in menus |
| `Function` | string | Yes | Name of the PowerShell function to invoke |
| `Category.Primary` | string | Yes | Top-level category label used in category menus |
| `Category.Subcategories` | string[] | No | Additional tags (informational only) |
| `Scopes` | string[] | No | Which environment types this test applies to (see below) |
| `RequiresAdmin` | bool | No | Set `true` if the test needs an elevated session. Default: `false` |
| `Enabled` | bool | No | Set `false` to prevent the test from loading. Default: `true` |
| `Maturity` | string | No | `Stable`, `Experimental`, or `WIP`. Default: `Experimental` |
| `Risk` | string | No | Operational risk of running the test: `Low`, `Medium`, `High`. Default: `Low` |
| `Description` | string | No | One-sentence summary shown in the search and detail views |
| `OS` | string | No | `Windows`, `Linux`. Inferred from folder if omitted. |
| `Strategy` | string | No | `Defensive`, `Offensive`. Inferred from folder if omitted. |

### Scopes

Use `Scopes` to control which environment targets show this test. The framework filters tests by scope when the operator chooses "Run Tests (Select Environment)".

| Value | When to use |
|-------|------------|
| `Workstation` | Desktop and laptop endpoints |
| `Server` | Member servers |
| `Domain` | Domain controllers |
| `All` | Applicable everywhere |

To match multiple scopes, list all that apply:

```json
"Scopes": ["Workstation", "Server"]
```

---

## 4. test.psm1 Structure

Every `test.psm1` has three sections:

1. **Framework mappings block** - MITRE ATT&CK, CWE, NIST, CIS references
2. **Mappings getter function** - called automatically by the framework
3. **Test function** - the actual check logic

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ================================================================
# Mappings : MitreAttack / CWE / NIST / CIS
# ================================================================
$script:Mappings = [pscustomobject]@{

    MitreAttack = @(
        [pscustomobject]@{
            Id     = "T1055"
            Name   = "Process Injection"
            Tactic = "Defense Evasion"
            Url    = "https://attack.mitre.org/techniques/T1055/"
        }
    )

    CWE = @(
        [pscustomobject]@{
            Id   = "CWE-693"
            Name = "Protection Mechanism Failure"
            Url  = "https://cwe.mitre.org/data/definitions/693.html"
        }
    )

    Nist = @(
        [pscustomobject]@{
            Id   = "AU-2"
            Name = "Event Logging"
            Url  = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    )

    CIS = @()
}

function fncGetMappings_SYSMON_INSTALL_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckSysmonInstallStatus
# ================================================================
function fncCheckSysmonInstallStatus {

    fncSafeSectionHeader "Sysmon Installation Check"

    $Risk       = "Low"
    $RiskReason = "Queries service registry and process list. Read-only."
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Checking for Sysmon installation..." "info"
    Write-Host ""

    $testId   = "SYSMON-INSTALL-CHECK"
    $evidence = @()

    # --- your check logic here ---

    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) {
        $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    }

    if ($svc -and $svc.Status -eq "Running") {

        $evidence += ("ServiceName={0}" -f $svc.Name)
        $evidence += ("Status=Running")

        fncTestMessage "Sysmon is installed and running." "proten"

        fncSubmitFinding `
            -Id          ("SYS-" + (fncShortHashTag "SYSMON_RUNNING")) `
            -Title       "Sysmon Running" `
            -Category    "Logging Monitoring" `
            -Severity    "Info" `
            -Status      "Protected" `
            -Message     "Sysmon service is installed and in a running state." `
            -Recommendation "Maintain current configuration and review Sysmon config regularly." `
            -Evidence    $evidence `
            -SourceTests @($testId) `
            -Exploitation "Sysmon is providing endpoint telemetry." `
            -Remediation  "No action required."

    } else {

        $evidence += "SysmonService=NotFound"
        fncTestMessage "Sysmon is not installed or not running." "specpriv"

        fncSubmitFinding `
            -Id          ("SYS-" + (fncShortHashTag "SYSMON_MISSING")) `
            -Title       "Sysmon Not Installed" `
            -Category    "Logging Monitoring" `
            -Severity    "Medium" `
            -Status      "Detected" `
            -Message     "Sysmon is not installed. Endpoint telemetry will be limited." `
            -Recommendation "Deploy Sysmon with a validated configuration such as SwiftOnSecurity or Olaf Hartong's modular config." `
            -Evidence    $evidence `
            -SourceTests @($testId) `
            -Exploitation "Without Sysmon, process creation, network connections and image load events are not captured." `
            -Remediation  "Install Sysmon using a community-maintained configuration. See https://github.com/SwiftOnSecurity/sysmon-config"
    }

    Write-Host ""
}

Export-ModuleMember -Function @(
    "fncCheckSysmonInstallStatus",
    "fncGetMappings_SYSMON_INSTALL_CHECK"
)
```

### Key rules

- `Set-StrictMode -Version Latest` and `$ErrorActionPreference = "Stop"` are required at the top of every test file. The framework runs under both.
- Never access a property that may not exist without a `try/catch` or an existence check first. StrictMode will throw on missing properties.
- Always export both functions in `Export-ModuleMember`.
- The mappings property for NIST uses `Nist` (not `NIST`) inside the `$script:Mappings` object.

---

## 5. Submitting Findings

Call `fncSubmitFinding` to record a result. The framework handles deduplication - if the same `Id` is submitted more than once for the same host, evidence is merged rather than creating a duplicate entry.

```powershell
fncSubmitFinding `
    -Id             "UNIQUE-FINDING-ID" `
    -Title          "Human-readable title" `
    -Category       "Category Name" `
    -Severity       "Medium" `
    -Status         "Detected" `
    -Message        "What was found." `
    -Recommendation "Short remediation guidance." `
    -Evidence       $evidence `
    -SourceTests    @($testId) `
    -Exploitation   "What an attacker could do with this." `
    -Remediation    "Step-by-step fix instructions."
```

### Parameter Reference

| Parameter | Required | Values / Notes |
|-----------|----------|---------------|
| `-Id` | Yes | Unique string. Use `fncShortHashTag` to generate a stable short hash from a descriptive label. |
| `-Title` | Yes | Short display name shown in menus and reports. |
| `-Category` | No | Should match `Category.Primary` in `test.json`. Default: `Uncategorised` |
| `-Severity` | No | `Critical`, `High`, `Medium`, `Low`, `Info`. Default: `Info` |
| `-Status` | No | Free text. Recommended values: `Detected`, `Protected`, `Not Configured`, `Partial` |
| `-Message` | No | One or two sentences describing the specific finding on this host. |
| `-Recommendation` | No | Brief remediation summary (one line). Used in the CSV and console view. |
| `-Evidence` | No | String array. Each item is a `Key=Value` observation from the check. |
| `-SourceTests` | No | String array of test IDs that produced this finding. Typically `@($testId)`. |
| `-Exploitation` | No | Free text. Explain what an attacker gains from this gap. Shown in the HTML report. |
| `-Remediation` | No | Detailed fix steps. Multi-line here-string is fine. Shown in the HTML report. |

### Generating stable finding IDs

Use `fncShortHashTag` with a descriptive constant label to generate a 5-character hash suffix. This keeps IDs short while staying stable across runs:

```powershell
# Produces a stable ID like "CG-3f7a1"
-Id ("CG-" + (fncShortHashTag "CREDENTIAL_GUARD_DISABLED"))
```

Use a different label for each distinct outcome so that "enabled" and "disabled" findings get different IDs:

```powershell
-Id ("SYS-" + (fncShortHashTag "SYSMON_RUNNING"))   # finding when present
-Id ("SYS-" + (fncShortHashTag "SYSMON_MISSING"))   # finding when absent
```

### Severity guidance

| Severity | When to use |
|----------|------------|
| `Critical` | The absence of this control directly enables a known critical attack path with no mitigating factors |
| `High` | Significant security gap. Exploitation is realistic and impact is material |
| `Medium` | Defense-in-depth gap. Exploitation may require additional conditions |
| `Low` | Minor hardening deviation. Limited direct impact |
| `Info` | Control is in place and correctly configured. Record the positive state |

---

## 6. Helper Functions Reference

These functions are available inside any test function.

### Output

| Function | Signature | Purpose |
|----------|-----------|---------|
| `fncTestMessage` | `fncTestMessage "text" "level"` | Print a message during test execution |
| `fncPrintRisk` | `fncPrintRisk "Low" "reason"` | Print the operational risk banner at the top of a test |
| `fncSafeSectionHeader` | `fncSafeSectionHeader "Title"` | Print a section header |
| `fncPrintMessage` | `fncPrintMessage "text" "level"` | General purpose message (used outside test context) |

**`fncTestMessage` levels:**

| Level | Symbol | Colour | Use for |
|-------|--------|--------|---------|
| `info` | `[i]` | Cyan | Neutral status updates |
| `warning` | `[!!]` | Yellow | Something worth noting |
| `specpriv` | `[!]` | Red | Security gap detected |
| `proten` | `[+]` | Green | Control is in place |
| `link` | `[>]` | Magenta | References / URLs |
| `section` | - | White | Sub-section headings |

**`fncPrintMessage` levels:** `success`, `info`, `warning`, `error`, `debug`

### Findings

| Function | Purpose |
|----------|---------|
| `fncSubmitFinding` | Record a finding (see Section 5) |
| `fncShortHashTag "label"` | Return a 5-char stable hash for use in finding IDs |

### Utility

| Function | Purpose |
|----------|---------|
| `fncSafeArray $value` | Return `$value` as an array. Never returns null. |
| `fncSafeString $value` | Return `$value` as a string. Never returns null. |
| `fncSafeCount $value` | Return the count of an array safely. Returns 0 on null. |
| `fncSafeGetProp $obj "Name" $default` | Return a property value or default if not present |
| `fncCommandExists "name"` | Return `$true` if the named function is currently loaded |
| `fncIsAdmin` | Return `$true` if the current session has Administrator privileges |

---

## 7. Framework Mappings

Mappings are defined in `$script:Mappings` at the top of `test.psm1`. The framework reads them automatically via the `fncGetMappings_*` getter and attaches them to findings submitted by that test.

You do not need to pass mappings to `fncSubmitFinding` explicitly - if `SourceTests` references your test ID, the mappings will be injected automatically.

### MITRE ATT&CK

```powershell
MitreAttack = @(
    [pscustomobject]@{
        Id     = "T1003"
        Name   = "OS Credential Dumping"
        Tactic = "Credential Access"
        Url    = "https://attack.mitre.org/techniques/T1003/"
    }
)
```

Find technique IDs at: https://attack.mitre.org/

### CWE

```powershell
CWE = @(
    [pscustomobject]@{
        Id   = "CWE-522"
        Name = "Insufficiently Protected Credentials"
        Url  = "https://cwe.mitre.org/data/definitions/522.html"
    }
)
```

Find CWE IDs at: https://cwe.mitre.org/

### NIST SP 800-53

```powershell
Nist = @(
    [pscustomobject]@{
        Id   = "AU-2"
        Name = "Event Logging"
        Url  = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    }
)
```

Common controls: `AC-*` (Access Control), `AU-*` (Audit), `CM-*` (Config Mgmt), `IA-*` (Identity), `SI-*` (System Integrity)

### CIS Controls

```powershell
CIS = @(
    [pscustomobject]@{
        Id   = "8.2"
        Name = "Collect Audit Logs"
        Url  = "https://www.cisecurity.org/controls/v8"
    }
)
```

Leave `CIS = @()` if there is no applicable CIS control.

---

## 8. Complete Example

Below is a minimal but complete test that checks whether Windows Firewall is enabled.

**Folder:** `Tests\Defensive\Windows\NetworkProtection\FIREWALL-PROFILE-CHECK\`

**test.json**

```json
{
    "SchemaVersion": 6,
    "Id":            "FIREWALL-PROFILE-CHECK",
    "Name":          "Windows Firewall Profile Validation",
    "Function":      "fncCheckFirewallProfiles",
    "Category": {
        "Primary":       "Network Protection",
        "Subcategories": ["Host Firewall", "Network Segmentation"]
    },
    "Scopes":        ["Workstation", "Server"],
    "RequiresAdmin": false,
    "Enabled":       true,
    "Maturity":      "Stable",
    "Risk":          "Low",
    "Description":   "Validates that the Windows Firewall is enabled across all network profiles.",
    "OS":            "Windows",
    "Strategy":      "Defensive"
}
```

**test.psm1**

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ================================================================
# Mappings
# ================================================================
$script:Mappings = [pscustomobject]@{

    MitreAttack = @(
        [pscustomobject]@{
            Id     = "T1562.004"
            Name   = "Disable or Modify System Firewall"
            Tactic = "Defense Evasion"
            Url    = "https://attack.mitre.org/techniques/T1562/004/"
        }
    )

    CWE = @(
        [pscustomobject]@{
            Id   = "CWE-693"
            Name = "Protection Mechanism Failure"
            Url  = "https://cwe.mitre.org/data/definitions/693.html"
        }
    )

    Nist = @(
        [pscustomobject]@{
            Id   = "SC-7"
            Name = "Boundary Protection"
            Url  = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    )

    CIS = @(
        [pscustomobject]@{
            Id   = "12.4"
            Name = "Establish and Maintain Architecture Diagram(s)"
            Url  = "https://www.cisecurity.org/controls/v8"
        }
    )
}

function fncGetMappings_FIREWALL_PROFILE_CHECK { return $script:Mappings }

# ================================================================
# Function: fncCheckFirewallProfiles
# ================================================================
function fncCheckFirewallProfiles {

    fncSafeSectionHeader "Windows Firewall Profile Check"

    $Risk       = "Low"
    $RiskReason = "Queries firewall state via Get-NetFirewallProfile. Read-only."
    fncPrintRisk $Risk $RiskReason

    fncTestMessage "Querying Windows Firewall profile states..." "info"
    Write-Host ""

    $testId   = "FIREWALL-PROFILE-CHECK"
    $evidence = @()
    $disabled = @()

    try {

        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($p in $profiles) {
            $evidence += ("{0}={1}" -f $p.Name, $p.Enabled)
            if (-not $p.Enabled) {
                $disabled += $p.Name
            }
        }

    }
    catch {
        fncTestMessage "Unable to query firewall profiles." "warning"
        $evidence += "QueryFailed=True"
    }

    if ($disabled.Count -eq 0) {

        fncTestMessage "All firewall profiles are enabled." "proten"

        fncSubmitFinding `
            -Id          ("FW-" + (fncShortHashTag "FIREWALL_ALL_ENABLED")) `
            -Title       "Windows Firewall Enabled (All Profiles)" `
            -Category    "Network Protection" `
            -Severity    "Info" `
            -Status      "Protected" `
            -Message     "Windows Firewall is active on all network profiles." `
            -Recommendation "Maintain current configuration." `
            -Evidence    $evidence `
            -SourceTests @($testId) `
            -Exploitation "Firewall is enabled. Host-based network filtering is active." `
            -Remediation  "No action required."

    } else {

        fncTestMessage ("Firewall disabled on profile(s): {0}" -f ($disabled -join ", ")) "specpriv"

        fncSubmitFinding `
            -Id          ("FW-" + (fncShortHashTag "FIREWALL_PROFILE_DISABLED")) `
            -Title       "Windows Firewall Disabled on One or More Profiles" `
            -Category    "Network Protection" `
            -Severity    "High" `
            -Status      "Detected" `
            -Message     ("Firewall disabled on: {0}." -f ($disabled -join ", ")) `
            -Recommendation "Re-enable Windows Firewall on all profiles via Group Policy." `
            -Evidence    $evidence `
            -SourceTests @($testId) `
            -Exploitation @"
A disabled firewall profile removes host-based network filtering for that
connection type. An attacker with access to the same network segment can
attempt inbound connections to any listening service without being blocked
by the host firewall.

Common attack paths:
- Lateral movement to exposed SMB / WinRM ports
- Exploitation of services not intended to be network-accessible
"@ `
            -Remediation  @"
Re-enable Windows Firewall on all profiles.

Group Policy path:
Computer Configuration ->
Windows Settings ->
Security Settings ->
Windows Defender Firewall with Advanced Security

Set all three profiles (Domain, Private, Public) to On.

Verify:
Get-NetFirewallProfile | Select Name, Enabled
"@
    }

    Write-Host ""
}

Export-ModuleMember -Function @(
    "fncCheckFirewallProfiles",
    "fncGetMappings_FIREWALL_PROFILE_CHECK"
)
```

---

## 9. Checklist

Before submitting a new test, verify all of the following:

**Manifest (test.json)**
- [ ] `SchemaVersion` is `6`
- [ ] `Id` matches the folder name exactly
- [ ] `Name` is human-readable and describes what is being checked
- [ ] `Function` matches the function name in `test.psm1`
- [ ] `Category.Primary` is consistent with other tests in the same category folder
- [ ] `Scopes` lists only the environment types where the test is relevant
- [ ] `RequiresAdmin` is set correctly
- [ ] `Maturity` is set to `Stable` only when the test has been validated
- [ ] `Strategy` is `Defensive`

**Implementation (test.psm1)**
- [ ] `Set-StrictMode -Version Latest` is at the top
- [ ] `$ErrorActionPreference = "Stop"` is at the top
- [ ] `$script:Mappings` is defined with all four keys (`MitreAttack`, `CWE`, `Nist`, `CIS`)
- [ ] Mappings getter is named `fncGetMappings_<ID_WITH_UNDERSCORES>`
- [ ] Test function name matches `"Function"` in `test.json`
- [ ] `fncSafeSectionHeader` is called at the top of the test function
- [ ] `fncPrintRisk` is called with an honest risk level and reason
- [ ] `fncSubmitFinding` is called for every meaningful outcome (both positive and negative where appropriate)
- [ ] Finding IDs use `fncShortHashTag` with distinct labels per outcome
- [ ] `SourceTests` is set to `@($testId)` where `$testId` matches the manifest `Id`
- [ ] `Exploitation` and `Remediation` fields are populated
- [ ] All property accesses inside `try/catch` blocks where the property may not exist
- [ ] No `??` operator used (PowerShell 5.1 incompatible)
- [ ] Both functions exported in `Export-ModuleMember`
- [ ] No `-` (em-dash) characters in the file (use `-` hyphen only)
