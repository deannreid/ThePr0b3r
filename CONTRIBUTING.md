# Contributing to THE Pr0b3r

First - thank you.

This project is built around structured, predictable tests.
If you’re contributing, consistency matters more than cleverness.

---

# Before You Submit a Test

Make sure your test:

* Uses **SchemaVersion 5**
* Matches `test.json` → `Function` name exactly
* Produces findings using `fncAddFinding`
* Prints meaningful console output
* Handles failure gracefully
* Does not break StrictMode

If your test crashes when RSAT is missing, Kerberos is absent, or the machine isn’t domain-joined - it’s not ready.

---

# Test Folder Structure

```plaintext
Tests/<Scope>/<Category-TestName>/
├── test.json
├── test.psm1
```

`test.psm1` is preferred over `test.ps1`.

---

# Pull Request Expectations

### ✔ Required

* Clean formatting
* No hardcoded domain names
* No environment-specific logic
* No silent `catch {}` blocks
* Deterministic Finding IDs
* Exploitation + Remediation narratives

### ✖ Not Accepted

* Duplicate logic already covered elsewhere
* Tests that only dump raw command output
* Vague remediation (“Harden system”)

---

# Code Style Rules

* `Set-StrictMode -Version Latest` compliant
* No global variable pollution
* Always define `$testId`
* Always use `fncPrintSectionHeader`
* Always use `fncPrintMessage`

Example:

```powershell
fncPrintSectionHeader "Example Check"
fncPrintMessage "Enumerating configuration..." "info"
```

---

# Finding Rules

Every finding must include:

* `-TestId`
* `-Id`
* `-Category`
* `-Title`
* `-Severity`
* `-Status`
* `-Message`
* `-Recommendation`
* `-Exploitation`
* `-Remediation`

If it’s exploitable - explain how.

If it’s secure - explain why it matters.

---

# Severity Discipline

Be realistic.

| Severity | Meaning                            |
| -------- | ---------------------------------- |
| Critical | Direct privilege/domain compromise |
| High     | Strong attacker leverage           |
| Medium   | Realistic misconfiguration         |
| Low      | Weakening condition                |
| Info     | Secure or informational state      |

Do not inflate severity.

---

# Deterministic IDs

Never generate random IDs.

Use:

```powershell
$fingerprint = "$Service|$Path|$Context"
$tag = fncShortHashTag $fingerprint
```

Stable IDs = deduped findings.

---

# Testing Your Test

Before submitting:

* Run in Workstation scope
* Run in Server scope
* Run as non-admin
* Run as admin
* Run on non-domain system
* Run on domain-joined system

If it breaks in any of those - fix it.

---

# Philosophy

This is not a script dump project.

It’s a structured framework.

Clarity > Noise
Precision > Drama
Actionable > Theoretical