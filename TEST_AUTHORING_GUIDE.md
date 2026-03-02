# 📄 TEST_AUTHORING_GUIDE.md

# Test Authoring Guide – THE Pr0b3r

This guide explains how to write high-quality tests for the SchemaVersion 5 framework.

---

# 1️⃣ Schema Version 5 Structure

Every test requires a `test.json` file.

Example:

```json
{
  "SchemaVersion": 5,
  "Id": "WDAC-CHECK",
  "Name": "Windows Defender Application Control Assessment",
  "Function": "fncCheckWDACPolicy",

  "Category": {
    "Primary": "Application Control",
    "Subcategories": [
      "Execution Prevention",
      "Code Integrity"
    ]
  },

  "Scopes": ["Workstation", "Server"],
  "RequiresAdmin": false,
  "Enabled": true,

  "Description": "Evaluates WDAC policy enforcement state.",

  "Mappings": {
    "MitreAttack": [...],
    "CWE": [...],
    "Nist": [...]
  }
}
```

---

# 2️⃣ Console Output Standards

Every test must:

1. Print a section header
2. Print what is being tested
3. Print state values discovered
4. Print conclusion

Example:

```powershell
fncPrintSectionHeader "WDAC Assessment"
fncPrintMessage "Checking Code Integrity registry..." "info"
```

Console output explains operator workflow.

Findings explain reporting impact.

Do both.

---

# 3️⃣ Writing Exploitation Narratives

Structure:

1. Precondition
2. Abuse method
3. Impact
4. Objective

Example (Service Abuse):

> If non-admin users can modify service configuration, they can replace the binary path or change service parameters. Upon service restart, attacker-controlled code executes in service context (often SYSTEM), resulting in privilege escalation.

Avoid:

* “Attacker can hack system”
* Generic wording
* Fear language

---

# 4️⃣ Writing Remediation Narratives

Structure:

1. Where to change
2. What to set
3. Why it matters
4. Monitoring guidance

Example:

> Remove write access from Authenticated Users on the service configuration.
> Validate via `sc sdshow`.
> Monitor service configuration changes via Event ID 7045.

Remediation must be actionable.

---

# 5️⃣ When to Produce Findings

Always produce something.

* Misconfiguration → Detected
* Secure state → Configured
* Missing dependency → Info with explanation
* Inconclusive → Unknown

Never silently exit.

---

# 6️⃣ Single Responsibility Rule

Each test should cover one logical control.

Bad:

* “Execution Surface Check” that covers WDAC + AppLocker + ExecutionPolicy + AMSI

Good:

* WDAC Enforcement Mode
* AppLocker DLL Enforcement
* Execution Policy (Global Scope)
* AMSI Tamper Detection

Granularity enables chaining later.

---

# 7️⃣ Mapping Rules

Mappings should reflect real relevance.

If the test relates to:

* Execution control → MITRE TA0002
* Priv Esc → TA0004
* Defense Evasion → TA0005

Do not over-map.

---

# 8️⃣ Advanced Test Quality

High-quality tests:

* Detect enforcement vs audit mode
* Detect bypass opportunity
* Explain exploit chain relevance
* Provide context-aware severity

---

# 9️⃣ Things to Avoid

* Raw command dumps
* Silent errors
* Catch-all try/catch swallowing failures
* Repeating logic from another test
* Overlapping coverage

---

# 🔟 Golden Rule

Every test must answer:

> “If I were attacking this machine, how does this help me?”

If it doesn’t help an attacker or defender - it doesn’t belong.