# Security Skills

Reusable skills for practical, evidence-based repository security reviews.

## Included skill

### `repository-security-audit`

Audits a source-code repository with:

- [Semgrep](https://semgrep.dev/) static analysis
- [Gitleaks](https://github.com/gitleaks/gitleaks) secret detection
- Repository-aware triage and deduplication
- A redacted Markdown report with prioritized remediation

The skill scans current files and, by default, Git history. It does not modify application code, validate discovered credentials against live services, or expose complete secrets in its report.

## Install

Install the skill for the current project:

```bash
npx skills add https://github.com/askvallejos/security-skills --skill repository-security-audit
```

The current project is the default installation scope. To make the skill available across projects, add `--global`:

```bash
npx skills add https://github.com/askvallejos/security-skills --skill repository-security-audit --global
```

The installer detects supported agents and prompts for the installation target.

## Use

After installation, reload your agent. For a project-scoped installation, work inside the project where the skill was installed.

Invoke it explicitly:

```text
Use the repository-security-audit skill to run a full security audit of this repository.
```

Examples:

```text
Use repository-security-audit to run a quick scan of ./services/api.
Use repository-security-audit to audit this repository and write docs/SECURITY_AUDIT.md.
Use repository-security-audit without installing missing scanners.
```

Agents that recognize `$skill-name` syntax can also invoke `$repository-security-audit`.

The default report is `SECURITY_AUDIT.md`; redacted scanner artifacts are stored under `.security-audit/`. Both paths can be changed when the audit must keep generated files outside the target repository.

## Requirements

The skill can locate or install Semgrep and Gitleaks using supported user-scoped methods. Package installation and network access remain subject to the host's approval controls.

## Repository layout

```text
security-skills/
├── README.md
└── skills/
    └── repository-security-audit/
        ├── SKILL.md
        └── references/
            └── reporting-and-triage.md
```

## Safety principles

- Never disclose complete secrets.
- Never authenticate with discovered credentials.
- Never claim a successful scan when coverage is incomplete.
- Never modify source code or Git history during an audit.
- Keep false-positive decisions grounded in repository evidence.

## Contributing

Keep skill instructions concise, preserve the redaction guarantees, and validate changes before publishing.
