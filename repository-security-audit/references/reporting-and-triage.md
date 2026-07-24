# Reporting and triage reference

Use this reference while classifying findings and writing the final audit report.

## Triage status

Assign exactly one status:

| Status | Meaning |
|---|---|
| **Confirmed** | Repository evidence directly demonstrates the insecure condition. |
| **Likely true positive** | Strong evidence indicates a real issue, but runtime or external confirmation is unavailable. |
| **Likely false positive** | Strong repository evidence shows the match is safe or intentionally non-secret. |
| **Needs human review** | Evidence is incomplete, ambiguous, environment-dependent, or requires business context. |

Assign confidence as `High`, `Medium`, or `Low`.

## Report severity

Use `Critical`, `High`, `Medium`, `Low`, or `Informational`. Preserve scanner severity separately.

Consider exploitability, attacker control, reachability, data sensitivity, privilege, current-tree versus historical exposure, possible credential validity, and visible compensating controls. Do not lower severity because remediation is inconvenient.

## Evidence rules

Safe evidence can include:

- Relative path and line range.
- Scanner rule and sanitized message.
- A redacted description of relevant code.
- Call-site or data-flow explanation.
- Commit identifier for historical exposure.
- Repository documentation that demonstrates a value is fake.

Never include:

- Complete credentials, tokens, passwords, private keys, or connection strings.
- Unnecessary source code or unrelated personal data.
- Guesses presented as facts.

## Overall result

- Use **Pass** only when both scanners completed successfully and no `Confirmed`, `Likely true positive`, or `Needs human review` findings remain.
- Use **Findings require action** when at least one actionable or unresolved finding exists.
- Use **Incomplete** when either scanner failed, an expected report could not be parsed, installation failed, or scope was materially restricted.

Never report `Pass` with incomplete coverage.

## Report template

```markdown
# Repository Security Audit

## Executive summary

- **Target:** `<relative or safe path>`
- **Scan date:** `<ISO-8601 timestamp>`
- **Mode:** `quick` or `full`
- **Overall result:** `Pass`, `Findings require action`, or `Incomplete`
- **Semgrep:** `<version and status>`
- **Gitleaks:** `<version and status>`

Summarize the most important result and material limitations.

## Scope and methodology

Describe the scanned scope, detected languages and frameworks, Git-history
coverage, configurations, exclusions, and incomplete coverage.

## Results summary

| Scanner | Raw | Deduplicated | Confirmed | Likely true | Likely false | Human review |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep | 0 | 0 | 0 | 0 | 0 | 0 |
| Gitleaks | 0 | 0 | 0 | 0 | 0 | 0 |

## Priority actions

1. Highest-priority remediation.
2. Secret rotation or history cleanup when applicable.
3. Configuration or code-hardening action.

## Findings

### SG-001 — Finding title

- **Scanner:** Semgrep
- **Rule:** `rule-id`
- **Severity:** High
- **Scanner severity:** ERROR
- **Status:** Likely true positive
- **Confidence:** High
- **Location:** `path/to/file.ext:10`
- **Evidence:** Sanitized, repository-grounded explanation.
- **Impact:** Concrete security consequence.
- **Remediation:** Specific corrective action.
- **False-positive rationale:** `Not applicable` or supporting evidence.

### GL-001 — Possible credential exposure

- **Scanner:** Gitleaks
- **Rule:** `provider-rule`
- **Severity:** Critical
- **Status:** Needs human review
- **Confidence:** Medium
- **Location:** `path/to/file.ext:20`
- **History:** Present in commit `<short hash>` or `Current tree only`
- **Evidence:** Value fully redacted; explain why it appears credential-like.
- **Impact:** Concrete consequence if valid.
- **Remediation:** Rotate or revoke, adopt secret management, and clean history when required.
- **False-positive rationale:** Evidence or `Insufficient evidence`.

## Likely false positives

List every likely false positive with its ID, evidence, and confidence. Keep each
finding in the main findings section too.

## Scanner and configuration details

### Semgrep

- Version:
- Installation method:
- Configuration:
- Exclusions:
- Duration:
- Exit code:
- Parse errors or skipped files:

### Gitleaks

- Version:
- Installation method:
- Configuration:
- Scans performed:
- Baseline:
- Duration:
- Exit codes:
- Parse errors or skipped files:

## Limitations

State what the audit could not establish, including runtime behavior, deployed
configuration, external service state, credential validity, incomplete history,
unsupported languages, unreadable files, or scanner failures.

## Artifacts

- Redacted Semgrep JSON: `.security-audit/raw/semgrep.json`
- Redacted Gitleaks directory JSON: `.security-audit/raw/gitleaks-dir.json`
- Redacted Gitleaks history JSON: `.security-audit/raw/gitleaks-git.json`
- Run metadata: `.security-audit/run-metadata.json`

## Recommended next steps

Provide prioritized actions and identify required human validation.
```
