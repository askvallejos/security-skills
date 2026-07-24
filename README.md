# Security Skills

Codex skills for practical, evidence-based repository security reviews.

## Included skill

### `repository-security-audit`

Audits a source-code repository with:

- [Semgrep](https://semgrep.dev/) static analysis
- [Gitleaks](https://github.com/gitleaks/gitleaks) secret detection
- Repository-aware triage and deduplication
- A redacted Markdown report with prioritized remediation

The skill scans current files and, by default, Git history. It does not modify application code, validate discovered credentials against live services, or expose complete secrets in its report.

## Install

Clone this repository, then copy or symlink the skill directory into your Codex skills directory:

```bash
git clone https://github.com/askvallejos/security-skills.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R security-skills/repository-security-audit \
  "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Restart Codex after installation so it discovers the skill.

## Use

Invoke the skill explicitly:

```text
Use $repository-security-audit to run a full security audit of this repository.
```

Examples:

```text
Use $repository-security-audit to run a quick scan of ./services/api.
Use $repository-security-audit to audit this repository and write docs/SECURITY_AUDIT.md.
Use $repository-security-audit without installing missing scanners.
```

The default report is `SECURITY_AUDIT.md`; redacted scanner artifacts are stored under `.security-audit/`. Both paths can be changed when the audit must keep generated files outside the target repository.

## Requirements

The skill can locate or install Semgrep and Gitleaks using supported user-scoped methods. Package installation and network access remain subject to the host's approval controls.

## Repository layout

```text
security-skills/
├── README.md
└── repository-security-audit/
    ├── SKILL.md
    ├── agents/
    │   └── openai.yaml
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

Keep skill instructions concise, preserve the redaction guarantees, and validate changes with Codex's skill validator before publishing.
