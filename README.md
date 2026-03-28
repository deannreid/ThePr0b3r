<img width="444" height="229" alt="image" src="https://github.com/user-attachments/assets/729927c3-aeb8-46d1-9708-11093b294e1e" />

# THE Pr0b3r

A PowerShell-based security assessment framework for Windows environments.
Run defensive control-validation checks, collect structured findings, and export results to CSV, JSON, or a self-contained HTML report.

---

## Overview

THE Pr0b3r is a menu-driven security assessment tool built entirely on PowerShell 5.1.
It discovers test plugins automatically from the filesystem, executes them against the local host, and stores every result as a structured finding that can be filtered, reviewed, and exported.

**Modes**

| Mode | Flag | Purpose |
|------|------|---------|
| Blue (defensive) | `-Strategy blue` | Security control validation - verify that hardening controls are in place |
| Red (offensive) | `-Strategy red` | Attack surface enumeration (not included in public release) |

The public release ships with **defensive (blue) tests only.**

---

## Requirements

- Windows PowerShell 5.1 or later
- Windows 10 / Windows Server 2016 or later
- Some tests require a local Administrator session (`RequiresAdmin: true` in their manifest)

No external dependencies. No internet connection required at runtime.

---

## Quick Start

```powershell
# Run with default settings (defensive mode, no console output)
.\thePr0b3r.ps1

# Run in blue (defensive) mode with info-level console output
.\thePr0b3r.ps1 -Strategy blue -logger info

# Verbose debug output
.\thePr0b3r.ps1 -Strategy blue -logger debug

# Show help
.\thePr0b3r.ps1 -ShowHelp

# Show version
.\thePr0b3r.ps1 -ShowVersion
```

---

## Parameters

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `-Strategy` | `red`, `blue` | `red` | Assessment strategy |
| `-logger` | `silent`, `info`, `debug` | `silent` | Console verbosity level |
| `-ShowHelp` | switch | - | Print usage and exit |
| `-ShowVersion` | switch | - | Print version and exit |

---

## Main Menu

```
=========== TEST EXECUTION ===========
  [1]  Run Tests (Environment: <detected>)
  [2]  Run Tests (Select Environment)
  [3]  Search Test
  [4]  Browse All Categories
  [A]  Run All Tests

=============== RESULTS ===============
  [5]  View Findings
  [6]  Export Findings to CSV
  [7]  Export Findings to HTML
  [8]  Export Findings to JSON

================ MODULES ==============
  [AD] Active Directory Console

  [R]  Reload Test Modules
  [Q]  Quit
```

### Environment Scopes

When running tests you can target a specific environment scope to limit which tests are presented:

| Scope | Description |
|-------|-------------|
| `Workstation` | Endpoint / desktop systems |
| `Server` | Member servers |
| `Domain` | Domain controllers and AD infrastructure |
| `All` | All tests regardless of scope |

---

## Test Discovery

Tests are loaded automatically at startup. The framework walks the `Tests\` directory tree looking for `test.json` manifest files. No registration or configuration is required - drop a valid test folder in and it will be picked up on the next run (or via **[R] Reload Test Modules**).

```
Tests\
  Defensive\
    Windows\
      CredentialProtection\
        CREDENTIAL-GUARD-CHECK\
          test.json
          test.psm1
      LoggingMonitoring\
        COMMANDLINE-LOGGING-CHECK\
          test.json
          test.psm1
```

Strategy (`Offensive` / `Defensive`) and OS (`Windows` / `Linux`) are inferred from folder position and can be overridden in `test.json`.

---

## Findings

Every test reports its results by calling `fncSubmitFinding`. Findings are stored in memory for the duration of the session and keyed by `Id:Hostname` to prevent duplicates across repeated runs.

**Severity levels:** `Critical` | `High` | `Medium` | `Low` | `Info`

Findings can be reviewed from the menu (**[5] View Findings**) and filtered by severity, or exported in bulk.

---

## Exports

All exports are written to:

```
exports\<HOSTNAME>-<RunId>\
```

inside the framework root directory. All three formats from a single session land in the same subfolder.

| Format | Filename | Contents |
|--------|----------|---------|
| CSV | `Findings_<timestamp>.csv` | Flat spreadsheet, one row per finding |
| JSON | `Findings_<timestamp>.json` | Structured document with run context and mappings |
| HTML | `ThePr0b3r_Report_<timestamp>.html` | Self-contained interactive report |

The HTML report is fully self-contained - no external assets, no internet required to open.

---

## Logging

Log files are written to:

```
Logs\<RunId>\thePr0b3r.log
```

Each run gets its own directory keyed by its unique run ID.

---

## Directory Structure

```
thePr0b3r.ps1          Entry point / runner
Modules\               Core framework modules
  Core.psm1
  Findings.psm1
  Export.psm1
  Registry.psm1
  Logging.psm1
  Output.psm1
  UI.*.psm1
  Menu.psm1
  Integrations.AD.psm1  (optional)
Tests\                 Test plugins (filesystem-discovered)
  Defensive\
    Windows\
    Linux\
  Offensive\            (not included in public release)
data\                  HTML report template
  ThePr0b3r_full.html
exports\               Export output (created at runtime)
Logs\                  Run logs (created at runtime)
```

---

## Writing Your Own Tests

See [TEST_AUTHORING.md](TEST_AUTHORING.md) for a complete guide to creating custom test plugins, including the full `test.json` schema, the `test.psm1` structure, available helper functions, and a worked example.

---

## Optional Integrations

| Module | Purpose | Status |
|--------|---------|--------|
| `Integrations.AD.psm1` | Active Directory enumeration console | Included |
| `Integrations.NIST.psm1` | NIST SP 800-53 control enrichment | Included |
| `Integrations.KEV.psm1` | CISA Known Exploited Vulnerabilities feed | Included |

Optional modules are loaded if present and silently skipped if not found.

---

## Version

**4.0.0**
