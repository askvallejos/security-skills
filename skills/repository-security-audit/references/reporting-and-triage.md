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
- Relevant non-Markdown configuration or test evidence.

Never include:

- Complete credentials, tokens, passwords, private keys, or connection strings.
- Unnecessary source code or unrelated personal data.
- Guesses presented as facts.

## Overall result

- Use **Pass** only when both scanners and the manual review completed, no
  actionable or unresolved finding remains, every applicable code-verifiable
  control was assessed, and no material capability gap or unknown remains.
- Use **Findings require action** when at least one actionable finding, `Partial`
  control, or `Missing` control exists.
- Use **Incomplete** when either scanner failed, an expected report could not be
  parsed, installation failed, review scope was materially restricted, or
  material controls remain `Unknown`.

Never report `Pass` with incomplete coverage.

## Report template

```markdown
# Repository Security Audit

## Executive summary

- **Result:** `Pass`, `Findings require action`, or `Incomplete`
- **Highest risk:** `<one sentence or None>`
- **Coverage:** controls `<earned>/<scorable> (<percentage>)`; evidence
  `<scorable>/<applicable> (<percentage>)`; files `<reviewed>/<eligible> (<percentage>)`
- **Material limitation:** `<one sentence or None>`

**Scope:** `<target>; <mode>; <commit>; Semgrep <version/status>; Gitleaks <version/status>`

## OWASP Top 10:2025 coverage

| Category | V/P/M/U | Coverage | Confidence | Main gap |
|---|---:|---:|---|---|
| A01 Broken Access Control | 0/0/0/0 | N/A | Low | None established |

Include all ten categories.

## Required actions

| Priority | Issue or missing capability | Evidence | Required action | Verify |
|---|---|---|---|---|
| P1 | `<concise root cause>` | `path/file.ext:line` | `<specific fix>` | `<test>` |

Group repeated occurrences. Include every distinct Critical and High root cause
and summarize related Medium and Low occurrences with counts. Omit this section
when no action is required.

## Material limitations

List only limitations that can change the result, one sentence each. Omit when
there are none.

## Detailed evidence

- Findings: `.security-audit/normalized/findings.json`
- Controls: `.security-audit/normalized/controls.json`
- File coverage: `.security-audit/normalized/file-coverage.json`
- Run metadata and scanner output: `.security-audit/`
```

## Brevity rules

- Keep the executive summary to four bullets.
- Keep each table cell to one sentence.
- Omit empty sections and non-material operational detail.
- Do not repeat an issue in prose after presenting it in a table.
- Do not list passing controls individually.
- Store complete sanitized evidence, scanner metadata, false-positive rationale,
  repeated locations, ASVS mappings, and file-level coverage in artifacts.
- Never achieve brevity by hiding an actionable root cause, material unknown, or
  result-changing limitation.
