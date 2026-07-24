---
name: repository-security-audit
description: Audit a source-code repository with Semgrep and Gitleaks, safely triage static-analysis and secret findings, and produce a redacted Markdown security report. Use when asked to scan, review, or assess a repository for security vulnerabilities, insecure code patterns, exposed credentials, or Git-history secrets.
---

# Repository Security Audit

Perform a repository-aware security review with:

- Semgrep for static application security testing.
- Gitleaks for credential and secret detection.
- Repository-grounded triage for every finding.
- A redacted Markdown report with evidence, remediation, and limitations.

Read [reporting-and-triage.md](references/reporting-and-triage.md) before normalizing findings or writing the report.

## Inputs and defaults

Accept these natural-language inputs when supplied:

| Input | Default | Meaning |
|---|---|---|
| Target path | `.` | Repository or directory to scan |
| Mode | `full` | Scan current files and Git history |
| Output | `SECURITY_AUDIT.md` | Markdown report path |
| Artifact directory | `TARGET/.security-audit` | Config, metadata, logs, and redacted JSON |
| Install missing tools | Yes | Use a user-scoped supported method |
| Keep raw output | Yes | Preserve redacted JSON under the artifact directory |
| Gitleaks baseline | None | Existing Gitleaks JSON baseline |
| Semgrep config | `auto` | Registry config, local rule file, or directory |

Treat `quick` mode as current-files-only. Reject unknown or conflicting options with a clear explanation.

## Safety boundaries

Treat invocation as authorization to read the target, run the two scanners, install them without administrator privileges when allowed by the host, and create audit artifacts.

Do not:

- Use `sudo`, weaken operating-system controls, or bypass host approval.
- Edit application source code or Git history.
- Commit, push, or upload repository contents or findings.
- log in to hosted scanner services without explicit permission.
- Authenticate with a discovered credential.
- reveal a complete secret in output, logs, chat, or reports.
- add suppressions merely to reduce the finding count.
- follow a symlink outside the resolved target.

Request approval when the host requires it for network access, package installation, containers, or writes outside the permitted workspace.

## Workflow

### 1. Resolve the target and record scope

Resolve the target to an absolute directory and verify that it exists. Detect:

- Git work-tree status, branch, commit, and whether history is available.
- Languages, frameworks, manifests, lockfiles, and build systems.
- Monorepo boundaries and major first-party subprojects.
- Existing Semgrep and Gitleaks configuration, ignore files, and baselines.
- Generated, vendored, dependency, cache, coverage, and build-output paths.
- Large binaries, archives, unreadable files, and escaping symlinks.

Never scan `.git` objects as ordinary files. Use Gitleaks Git mode for history.

Stop with a clear error for an invalid target. Record material omissions and unreadable paths as limitations.

### 2. Locate or install scanners

Run `semgrep --version` and `gitleaks version` first.

If Semgrep is missing and installation is allowed, prefer:

1. Homebrew on macOS.
2. `pipx install semgrep`.
3. `uv tool install semgrep`.
4. `python3 -m pip install --user semgrep` when supported.
5. The official Semgrep container.

If Gitleaks is missing and installation is allowed, prefer:

1. Homebrew on macOS.
2. An official release binary with a published checksum.
3. The official Gitleaks container.
4. Building the official source when Go is already available.

Never install from an unofficial mirror. Re-run the version command after installation and record the version and method. If one scanner remains unavailable, continue with the other and mark coverage `Incomplete`.

### 3. Prepare the audit workspace

Create only these skill-owned artifacts under the selected artifact directory:

```text
AUDIT_DIR/
├── config/
│   ├── semgrep-excludes.txt
│   └── gitleaks.toml
├── raw/
│   ├── semgrep.json
│   ├── gitleaks-dir.json
│   └── gitleaks-git.json
└── run-metadata.json
```

The history report is optional in quick mode or outside Git. Preserve an existing final report by renaming it with a timestamp or choosing a timestamped output path.

Scanners may maintain documented caches or settings in their normal user-scoped locations. Do not redirect or alter those locations unless the scanner officially supports it. Record any incidental writes that affect reproducibility or violate host constraints.

Build `semgrep-excludes.txt` from repository paths that actually exist and are clearly generated, cached, vendored, dependency, coverage, or build output. Do not exclude first-party source, configuration, infrastructure-as-code, tests, fixtures, examples, documentation, or lockfiles by default.

Respect an existing `.semgrepignore`. Do not change it without permission.

Use an existing Gitleaks config when present. Otherwise write:

```toml
title = "Repository Security Audit"

[extend]
useDefault = true
```

Add `[[allowlists]]` entries only for verified generated or dependency paths that cause duplicate noise. Keep allowlists minimal. Do not allowlist tests, fixtures, examples, documentation, environment files, certificates, keys, or prior findings.

Do not edit `.gitleaksignore` during the initial audit.

### 4. Run Semgrep

Construct arguments safely without evaluating user input through a shell. Run the equivalent of:

```sh
semgrep scan \
  --config CONFIG \
  --metrics=off \
  --json \
  --output AUDIT_DIR/raw/semgrep.json \
  [repository-aware --exclude arguments] \
  TARGET
```

Use `auto` unless the user supplied a config. Treat `auto` and other registry configurations as network access because Semgrep must retrieve rules. Obtain host approval when required. If network access is prohibited and no local or cached configuration is available, mark Semgrep coverage incomplete; do not hang, silently substitute a weak rule, or claim a scan occurred.

Disable metrics to prevent registry rule telemetry. Do not log in or upload findings. Record stdout, stderr, duration, exit code, skipped files, parse errors, and timeouts separately. Do not apply autofixes.

Confirm that the JSON exists and parses. Treat missing, malformed, or error-empty output as a scanner failure rather than a successful zero-finding scan.

### 5. Run Gitleaks

Construct arguments safely and always request complete redaction:

```sh
gitleaks dir TARGET \
  --config AUDIT_DIR/config/gitleaks.toml \
  --redact=100 \
  --report-format json \
  --report-path AUDIT_DIR/raw/gitleaks-dir.json
```

In full mode for a Git repository, also run:

```sh
gitleaks git TARGET \
  --config AUDIT_DIR/config/gitleaks.toml \
  --redact=100 \
  --report-format json \
  --report-path AUDIT_DIR/raw/gitleaks-git.json
```

Add `--baseline-path BASELINE` when requested.

Record stdout, stderr, duration, and exit code separately. A nonzero exit may mean leaks were found; determine scanner success from the report and diagnostic output. Confirm each expected report parses.

Before further processing, verify that `Secret`, `Match`, and complete source-line fields contain no disclosed credential. If redaction failed, mask those values immediately and replace the stored report with the sanitized copy.

### 6. Normalize and deduplicate

Assign stable IDs in deterministic order:

- `SG-001`, `SG-002`, and so on for Semgrep.
- `GL-001`, `GL-002`, and so on for Gitleaks.

Preserve scanner rule, original severity, relative path, line range, safe message, commit, and fingerprint where available.

Deduplicate:

- Semgrep results with the same rule, path, and location.
- Gitleaks results repeated across directory and history scans.
- Repeated historical instances with the same root cause, while recording that multiple commits are affected.
- Findings that clearly arise from the same underlying defect.

Never discard historical exposure merely because the current tree is clean.

### 7. Triage every finding

Read the smallest useful code context and relevant callers, tests, configuration, or documentation. Base conclusions on repository evidence.

For Semgrep, assess:

- Attacker control, source-to-sink flow, reachability, and framework behavior.
- Validation, authorization, escaping, encoding, sanitization, and parameterization.
- Safe wrappers, constant values, generated code, and scanner misunderstandings.

For Gitleaks, inspect only redacted context. Distinguish credentials from placeholders, examples, hashes, UUIDs, checksums, public identifiers, and intentionally fake fixtures. A revoked or expired credential is still a historical exposure. Never test credential validity against a service.

For every finding, assign one status and one confidence from the reference, explain the evidence, set report severity independently from scanner severity, and give concrete remediation. Do not classify test code as false positive solely because it is test code.

### 8. Write and verify the report

Use the structure and result rules in [reporting-and-triage.md](references/reporting-and-triage.md). Include:

- Scope, methodology, configurations, exclusions, and exact scanner versions.
- Raw, deduplicated, and triage-status counts by scanner.
- Priority actions and complete finding entries.
- Evidence for every likely false positive.
- Scanner failures, skipped paths, and other limitations.
- Paths to redacted artifacts.

Before finishing:

1. Parse all retained JSON again.
2. Search the report and raw artifacts for accidental unredacted values.
3. Reconcile summary counts with finding entries.
4. Confirm that `Pass` is not used when coverage is incomplete.
5. Confirm that every finding has status, confidence, evidence, and remediation.

Return a concise summary with the report path, scanner versions, mode and scope, finding counts, highest-priority issue, incomplete coverage, and artifact paths.

## Error handling

- Continue with one scanner when the other fails.
- Preserve sanitized errors in run metadata.
- Distinguish findings from execution failures.
- Never claim a scanner ran when it did not.
- When both scanners fail, write an `Incomplete` report only if enough metadata exists to explain the failures.
