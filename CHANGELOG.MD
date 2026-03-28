# Changelog

All notable changes to THE Pr0b3r are documented in this file.

---

## [4.2.0] - 2026-03-27

### Added

#### Cross-Platform Support
- Full PowerShell Core support for Linux and macOS (PowerShell 7+)
- Automatic platform detection across all core modules (`$IsLinux`, `$IsMacOS`, `$IsWindows`)
- Registry module now gracefully no-ops on non-Windows platforms
- Cross-platform path handling throughout Core, Export, UI.Operator, and UI.Render modules

- `data/ThePr0b3r_blank.html` - Self-contained HTML report with MITRE ATT&CK, CWE, and CIS mapping visualisations

### Changed

#### Core Module Housekeeping
- Removed deprecated helper functions from `Core.psm1`, `Findings.psm1`, `Output.psm1`, and `UI.Framework.psm1`
- Consolidated export logic; `Export.HTML.psm1` merged into `Export.psm1`
- `UI.Browser.psm1` extended with improved test filtering and display
- Removed the user confirmation prompt for offensive test execution (tests are inherently scoped by strategy selection)

#### UI / Output
- Output colour scheme updated: informational/header elements shifted from blue to red accent palette
- Fixed visual rendering bug when tests flagged as `RequiresAdmin` were displayed in non-elevated sessions
- Fixed metabubble rendering in HTML export

### Removed

- Deprecated/unused functions across Core, Findings, Output, Registry, and UI modules
- Removed legacy `Export.HTML.psm1` module; all export functionality now consolidated in `Export.psm1`
- Removed the user confirmation prompt for offensive test execution (tests are inherently scoped by strategy selection)
- 

---

## [4.0.0] - Initial Release

- Core PowerShell security assessment framework
- Modular test plugin architecture with JSON manifests
- Findings engine with severity scoring and deduplication
- Interactive menu-driven shell
- CSV export formats
- NIST SP 800-53 and CISA KEV integration modules
