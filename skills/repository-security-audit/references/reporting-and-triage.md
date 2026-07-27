# Reporting and triage

## Contents

- Finding triage
- Severity
- Evidence
- Completion and disposition
- Report template
- Brevity

## Finding triage

Assign exactly one status:

| Status | Meaning |
|---|---|
| **Confirmed** | Repository evidence directly demonstrates the insecure condition. |
| **Likely true positive** | Strong evidence indicates a real issue, but runtime or external confirmation is unavailable. |
| **Likely false positive** | Strong repository evidence shows the match is safe or intentionally non-secret. |
| **Needs human review** | Evidence is ambiguous, environment-dependent, or requires business context. |

Assign confidence as `High`, `Medium`, or `Low`.

Never classify a test, fixture, example, or historical secret as false positive
solely because of its location. Never validate a credential against a service.

## Severity

Assign report severity independently from scanner severity:

- `Critical`: practical compromise of high-value systems, identities, keys, or
  sensitive data is imminent or already enabled.
- `High`: exploitation is practical and can cause major confidentiality,
  integrity, availability, authorization, or supply-chain impact.
- `Medium`: exploitation requires meaningful conditions or has constrained
  impact, but remediation is still required.
- `Low`: limited exploitability or impact with a concrete security consequence.
- `Informational`: defense-in-depth improvement without a demonstrated
  vulnerability.

Consider attacker control, reachability, trust boundaries, privilege, data
sensitivity, current versus historical exposure, credential validity unknowns,
and visible compensating controls. Do not lower severity because remediation is
inconvenient.

## Evidence

Safe evidence can include:

- Relative path and line range.
- Scanner rule and sanitized message.
- A redacted description of the relevant behavior.
- Source-to-sink or call-flow explanation.
- Commit identifier for historical exposure.
- Non-secret configuration, tests, and negative searches.
- Package, installed version, advisory identifier, and fixed-version guidance.

Never retain:

- Complete credentials, passwords, tokens, connection strings, or private keys.
- Scanner source-line, match, metavariable, author-email, or commit-message
  fields that can reproduce a secret or unnecessary personal data.
- Long code excerpts, unrelated personal data, or guesses stated as facts.

For a manual finding, use the findings schema and assign the next stable
`MAN-###` identifier. For multiple instances with one root cause, create one
finding and list every material location in `evidence`.

## Completion and disposition

Report two independent values:

### Completion

- **Complete**: all required scanners completed or were evidence-based
  `not_applicable`; every eligible file was manually reviewed; every initialized
  control was classified; no material scope or context limitation remains.
- **Incomplete**: a required scanner failed, was blocked, or was unavailable;
  expected scanner output was malformed; material files were unreviewed;
  advisory coverage was missing; controls remain `Unknown`; or business/runtime
  context could change the result. A `Needs human review` finding or an
  unassigned non-false-positive severity also keeps completion incomplete.

### Disposition

- **Pass**: completion is complete and no actionable finding, `Partial` control,
  or `Missing` control remains.
- **Findings require action**: at least one confirmed or likely-true-positive
  finding, `Partial` control, or `Missing` control exists.
- **Undetermined**: completion is incomplete and no actionable issue has yet
  been established.

An assessment can be `Incomplete` and `Findings require action` at the same
time. Never hide known risk behind an incomplete label.

## Report template

```markdown
# Repository Security Audit

## Executive summary

- **Completion:** `Complete` or `Incomplete`
- **Disposition:** `Pass`, `Findings require action`, or `Undetermined`
- **Highest risk:** `<one sentence or None established>`
- **Coverage:** verified controls `<verified>/<scorable> (<percentage>)`;
  evidence `<scorable>/<applicable> (<percentage>)`; manual files
  `<reviewed>/<eligible> (<percentage>)`
- **Material limitation:** `<one sentence or None>`

**Scope:** `<target>; profile and level; mode; commit; exact scanner versions>`

## Required actions

| Priority | Root cause | Evidence | Required action | Verify |
|---|---|---|---|---|
| P1 | `<concise defect or missing capability>` | `path/file.ext:line` | `<specific remediation>` | `<test or observation>` |

## OWASP Top 10:2025

| Category | Disposition | Evidence confidence | Main finding, gap, or limitation |
|---|---|---|---|
| A01 Broken Access Control | `Satisfied`, `Action required`, `Unknown`, or `N/A` | High, Medium, or Low | `<one sentence>` |

Include all ten categories. Do not invent a numeric category score.

## Material limitations

- `<only limitations that can change completion or disposition>`

## Detailed evidence

- Findings: `normalized/findings.json`
- Controls: `normalized/controls.json`
- Coverage: `normalized/coverage.json`
- File coverage: `normalized/file-coverage.json`
- Scanner evidence and run metadata: `scanner/` and `run-metadata.json`
```

Omit `Required actions` only when disposition is `Pass` or `Undetermined`.
Omit `Material limitations` only when completion is `Complete`.

Group repeated occurrences by root cause. Show every distinct Critical and High
root cause. Summarize related Medium and Low occurrences without hiding counts
or required remediation.

## Brevity

- Keep the executive summary to five bullets plus one scope line.
- Keep each table cell to one sentence.
- Do not repeat a table entry in prose.
- Do not list passing controls individually.
- Store complete sanitized evidence, ASVS or generic control classifications,
  false-positive rationale, repeated locations, and file coverage in JSON.
- Never gain brevity by hiding actionable risk, unknown context, incomplete
  coverage, or a required verification step.
