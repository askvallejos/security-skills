# Standards and scope

## Contents

- Applicability
- ASVS baseline
- OWASP Top 10
- Supply-chain coverage
- Attribution

## Applicability

Use the `web` profile only for a web application, web API, or web service. Ask
for the desired ASVS assurance level when repository evidence does not establish
it. Default to Level 1 and record that assumption.

Use the `generic` profile for libraries, command-line tools, infrastructure
repositories, desktop applications, mobile applications, and mixed repositories
whose primary security model is not a web application. Use a more specific
standard in addition to the generic baseline when the target clearly requires
one; do not force ASVS controls onto an inapplicable target.

For monorepos, select a profile per first-party subproject. Do not merge
incompatible denominators into a single percentage. Report each profile
separately and provide raw counts.

## ASVS baseline

`asvs-5.0.0.flat.json` is the pinned English OWASP ASVS 5.0.0 flat JSON release.
Initialize the full selected level with:

```sh
python3 SKILL_DIR/scripts/audit_tools.py init-controls \
  --profile web \
  --level 1 \
  --output RUN_DIR/normalized/controls.json
```

Assess every initialized control. Use versioned identifiers such as
`v5.0.0-1.2.5`. Do not delete inconvenient, unknown, missing, or not-applicable
controls from the baseline. Prove `Not applicable` with repository or confirmed
business-context evidence.

## OWASP Top 10

Assess all ten OWASP Top 10:2025 categories explicitly. Treat the Top 10 as a
risk taxonomy, not as a complete control standard. Do not manufacture numeric
Top 10 coverage by automatically mapping unrelated ASVS requirements. Map a
control or finding only when its evidence directly supports the category.

## Supply-chain coverage

Use OSV-Scanner for supported manifests and lockfiles. A completed OSV scan
establishes known-vulnerability coverage only for the packages, ecosystems, and
advisory data it actually inspected. It does not establish build integrity,
provenance, CI/CD least privilege, or safety of unpinned remote inputs.

If supported lockfiles exist and OSV-Scanner is unavailable, blocked, or fails,
mark dependency-vulnerability coverage incomplete. If no supported lockfile
exists, inspect manifests and record the resulting limitation rather than
claiming that dependencies are clean.

## Attribution

The bundled ASVS data is from the OWASP Application Security Verification
Standard 5.0.0 English flat JSON release:

- Source: <https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release>
- File: `OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json`
- SHA-256: `8201b20eec2908c3380ac600c91c8ba746346fbb808859366abb232027532311`
- License: [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)

The repository-security-audit skill does not modify the bundled ASVS text.
