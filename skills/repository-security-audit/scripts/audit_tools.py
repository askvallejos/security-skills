#!/usr/bin/env python3
"""Deterministic helpers for repository-security-audit.

The scanner runner never executes target code. Raw scanner reports live in a
private temporary directory and are reduced to sanitized evidence before the
temporary directory is deleted.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


SKILL_ROOT = Path(__file__).resolve().parent.parent
ASVS_PATH = SKILL_ROOT / "references" / "asvs-5.0.0.flat.json"
ASVS_SHA256 = "8201b20eec2908c3380ac600c91c8ba746346fbb808859366abb232027532311"
GENERIC_CONTROLS_PATH = SKILL_ROOT / "references" / "repository-controls.json"

TRIAGE_STATUSES = {
    "Confirmed",
    "Likely true positive",
    "Likely false positive",
    "Needs human review",
}
CONFIDENCES = {"High", "Medium", "Low"}
REPORT_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
    "Unassigned",
}
CONTROL_STATES = {
    "Verified",
    "Partial",
    "Missing",
    "Unknown",
    "Not applicable",
}
FILE_STATUSES = {"manually_reviewed", "scanner_only", "both", "unreviewed"}
FINDING_SOURCES = {"Semgrep", "Gitleaks", "OSV-Scanner", "Manual"}

DEPENDENCY_DIRS = {
    ".bundle",
    ".gradle",
    ".m2",
    ".next",
    ".nuxt",
    ".terraform",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}

SUPPORTED_LOCKFILES = {
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "bun.lock",
    "cabal.project.freeze",
    "composer.lock",
    "conan.lock",
    "deps.json",
    "gems.locked",
    "go.mod",
    "gradle.lockfile",
    "mix.lock",
    "package-lock.json",
    "packages.config",
    "packages.lock.json",
    "pdm.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pubspec.lock",
    "pylock.toml",
    "requirements.txt",
    "renv.lock",
    "stack.yaml.lock",
    "uv.lock",
    "yarn.lock",
}

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
]


class AuditError(RuntimeError):
    """A safe, user-facing audit error."""


def utc_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"Cannot parse JSON {path}: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise AuditError(f"Cannot read {path}: {error}") from error
    return digest.hexdigest()


def relative_path(path: str, target: Path) -> str:
    candidate = Path(path)
    try:
        if candidate.is_absolute():
            return candidate.resolve().relative_to(target).as_posix()
    except (OSError, ValueError):
        pass
    return candidate.as_posix().lstrip("./")


def sanitize_text(value: Any, known_secrets: Iterable[str] = ()) -> str:
    text = str(value or "")
    for secret in known_secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b"
        r"(\s*[:=]\s*)([^\s,;]{8,})",
        r"\1\2[REDACTED]",
        text,
    )
    return text


def sanitize_json_value(value: Any, known_secrets: Iterable[str] = ()) -> Any:
    if isinstance(value, dict):
        return {
            sanitize_text(key, known_secrets): sanitize_json_value(child, known_secrets)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize_json_value(child, known_secrets) for child in value]
    if isinstance(value, str):
        return sanitize_text(value, known_secrets)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text(value, known_secrets)


def command_result(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: int,
    env: Optional[Dict[str, str]] = None,
    stdout_path: Optional[Path] = None,
) -> Tuple[Dict[str, Any], str, str]:
    started = time.monotonic()
    try:
        if stdout_path is None:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd),
                env=env,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
            )
            stdout = completed.stdout
        else:
            descriptor = os.open(
                stdout_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", errors="replace") as output:
                completed = subprocess.run(
                    list(command),
                    cwd=str(cwd),
                    env=env,
                    check=False,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    timeout=timeout,
                )
            stdout = ""
        result = {
            "command": list(command),
            "duration_seconds": round(time.monotonic() - started, 3),
            "exit_code": completed.returncode,
            "timed_out": False,
        }
        return result, stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        result = {
            "command": list(command),
            "duration_seconds": round(time.monotonic() - started, 3),
            "exit_code": None,
            "timed_out": True,
        }
        stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        return result, stdout, stderr


def tool_version(
    executable: str,
    arguments: Sequence[str],
    target: Path,
    env: Optional[Dict[str, str]] = None,
) -> str:
    result, stdout, stderr = command_result(
        [executable, *arguments], cwd=target, timeout=30, env=env
    )
    if result["exit_code"] != 0:
        return "unknown"
    return sanitize_text((stdout or stderr).strip().splitlines()[0])


def is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(8192)
    except OSError:
        return True


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def discover_files(
    target: Path, artifact_root: Path
) -> Tuple[List[Dict[str, Any]], List[str], List[str], List[str]]:
    target = target.resolve()
    artifact_root = artifact_root.resolve()
    files: List[Dict[str, Any]] = []
    scanner_excludes: Set[str] = {".git"}
    escaping_symlinks: List[str] = []
    lockfiles: List[str] = []

    artifact_relative: Optional[str] = None
    if path_is_within(artifact_root, target):
        artifact_relative = artifact_root.resolve().relative_to(target).as_posix()
        scanner_excludes.add(artifact_relative)

    for root, directories, filenames in os.walk(target, followlinks=False):
        root_path = Path(root)
        kept_directories: List[str] = []
        for directory in sorted(directories):
            candidate = root_path / directory
            relative = candidate.relative_to(target).as_posix()
            if relative == ".git" or relative.startswith(".git/"):
                continue
            if artifact_relative and (
                relative == artifact_relative
                or relative.startswith(artifact_relative + "/")
            ):
                continue
            if candidate.is_symlink():
                if not path_is_within(candidate, target):
                    escaping_symlinks.append(relative)
                    scanner_excludes.add(relative)
                continue
            if directory in DEPENDENCY_DIRS:
                scanner_excludes.add(relative)
                continue
            kept_directories.append(directory)
        directories[:] = kept_directories

        for filename in sorted(filenames):
            candidate = root_path / filename
            relative = candidate.relative_to(target).as_posix()
            if candidate.is_symlink() and not path_is_within(candidate, target):
                escaping_symlinks.append(relative)
                scanner_excludes.add(relative)
                continue
            if not candidate.is_file():
                continue
            binary = is_binary(candidate)
            eligible = not binary
            reason = None if eligible else "binary or unreadable"
            files.append(
                {
                    "path": relative,
                    "eligible": eligible,
                    "exclusion_reason": reason,
                    "manual_status": "unreviewed" if eligible else None,
                    "scanner_coverage": [],
                }
            )
            if filename in SUPPORTED_LOCKFILES and eligible:
                lockfiles.append(relative)

    return (
        sorted(files, key=lambda item: item["path"]),
        sorted(scanner_excludes),
        sorted(escaping_symlinks),
        sorted(lockfiles),
    )


def toml_string(value: str) -> str:
    return json.dumps(value)


def build_gitleaks_config(
    target: Path,
    run_dir: Path,
    base_config: Optional[Path],
    scanner_excludes: Sequence[str],
) -> Path:
    if base_config:
        try:
            base = base_config.read_text(encoding="utf-8")
        except OSError as error:
            raise AuditError(f"Cannot read Gitleaks config {base_config}: {error}") from error
    else:
        base = 'title = "Repository Security Audit"\n\n[extend]\nuseDefault = true\n'

    patterns = []
    for relative in scanner_excludes:
        escaped = re.escape(relative.rstrip("/"))
        patterns.append(r"(^|/)" + escaped + r"(/|$)")

    if patterns:
        base += (
            "\n\n[[allowlists]]\n"
            'description = "Repository security audit exclusions"\n'
            "paths = [\n"
        )
        for pattern in sorted(patterns):
            base += f"  {toml_string(pattern)},\n"
        base += "]\n"

    output = run_dir / "config" / "gitleaks.toml"
    atomic_write_text(output, base)
    return output


def private_environment(temporary_path: Optional[Path] = None) -> Dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "GITLEAKS_CONFIG",
        "GITLEAKS_CONFIG_TOML",
        "SEMGREP_APP_TOKEN",
    ):
        environment.pop(key, None)
    environment["SEMGREP_SEND_METRICS"] = "off"
    if temporary_path is not None:
        environment["SEMGREP_LOG_FILE"] = str(temporary_path / "semgrep.log")
        environment["SEMGREP_SETTINGS_FILE"] = str(
            temporary_path / "semgrep-settings.yml"
        )
        environment["SEMGREP_VERSION_CACHE_PATH"] = str(
            temporary_path / "semgrep-version-cache"
        )
    if "SSL_CERT_FILE" not in environment:
        system_certificates = Path("/etc/ssl/cert.pem")
        if system_certificates.is_file():
            environment["SSL_CERT_FILE"] = str(system_certificates)
    return environment


def read_optional_report(path: Path, successful_empty: bool = False) -> Any:
    if path.exists():
        return load_json(path)
    if successful_empty:
        return []
    raise AuditError(f"Expected scanner report was not created: {path}")


def sanitize_semgrep(raw: Any, target: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not isinstance(raw, dict) or not isinstance(raw.get("results", []), list):
        raise AuditError("Semgrep output has an unexpected JSON shape")
    retained_results: List[Dict[str, Any]] = []
    normalized: List[Dict[str, Any]] = []
    for result in raw.get("results", []):
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}
        metadata = extra.get("metadata") or {}
        safe_metadata = {
            key: sanitize_json_value(metadata[key])
            for key in ("category", "confidence", "cwe", "owasp", "technology")
            if key in metadata
        }
        rule_id = sanitize_text(result.get("check_id") or "unknown")
        result_path = sanitize_text(
            relative_path(str(result.get("path") or ""), target)
        )
        retained = {
            "rule_id": rule_id,
            "path": result_path,
            "start": {"line": start.get("line"), "column": start.get("col")},
            "end": {"line": end.get("line"), "column": end.get("col")},
            "message": (
                f"Semgrep rule {rule_id} matched; source excerpt and interpolated "
                "message were removed."
            ),
            "scanner_severity": str(extra.get("severity") or "UNKNOWN"),
            "fingerprint": str(extra.get("fingerprint") or ""),
            "metadata": safe_metadata,
        }
        retained_results.append(retained)
        normalized.append(
            {
                "source": "Semgrep",
                "rule_id": retained["rule_id"],
                "scanner_severity": retained["scanner_severity"],
                "report_severity": "Unassigned",
                "triage_status": "Needs human review",
                "confidence": "Low",
                "path": retained["path"],
                "line_start": retained["start"]["line"],
                "line_end": retained["end"]["line"],
                "message": retained["message"],
                "commits": [],
                "fingerprint": retained["fingerprint"],
                "evidence": [],
                "impact": "",
                "remediation": "",
            }
        )
    safe_errors = []
    for error in raw.get("errors", []) if isinstance(raw.get("errors", []), list) else []:
        safe_errors.append(
            {
                "type": sanitize_text(error.get("type")),
                "level": sanitize_text(error.get("level")),
                "message": "Semgrep reported a scan or parse error; raw details were not retained.",
                "path": sanitize_text(
                    relative_path(str(error.get("path") or ""), target)
                ),
            }
        )
    raw_paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
    scanned_paths = [
        sanitize_text(relative_path(str(path), target))
        for path in raw_paths.get("scanned", [])
        if isinstance(path, str)
    ]
    skipped_paths = []
    for skipped in raw_paths.get("skipped", []):
        if isinstance(skipped, str):
            skipped_paths.append(
                {
                    "path": sanitize_text(relative_path(skipped, target)),
                    "reason": "Semgrep skipped this path.",
                }
            )
        elif isinstance(skipped, dict):
            skipped_paths.append(
                {
                    "path": sanitize_text(
                        relative_path(str(skipped.get("path") or ""), target)
                    ),
                    "reason": sanitize_text(
                        skipped.get("reason") or "Semgrep skipped this path."
                    ),
                }
            )
    retained_report = {
        "version": sanitize_text(raw.get("version")),
        "results": retained_results,
        "errors": safe_errors,
        "paths": {
            "scanned": sorted(set(scanned_paths)),
            "skipped": sorted(
                skipped_paths, key=lambda item: (item["path"], item["reason"])
            ),
        },
    }
    return retained_report, normalized


def add_scanner_coverage(
    files: List[Dict[str, Any]], paths: Iterable[str], scanner: str
) -> None:
    covered = set(paths)
    for file_record in files:
        if file_record["path"] in covered:
            scanners = set(file_record.get("scanner_coverage") or [])
            scanners.add(scanner)
            file_record["scanner_coverage"] = sorted(scanners)


def sanitize_gitleaks(
    raw: Any,
    target: Path,
    source_name: str,
    baseline_fingerprints: Optional[Set[str]] = None,
    repository_ignored_fingerprints: Optional[Set[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Set[str]]:
    if not isinstance(raw, list):
        raise AuditError(f"{source_name} output has an unexpected JSON shape")
    retained: List[Dict[str, Any]] = []
    normalized: List[Dict[str, Any]] = []
    secrets: Set[str] = set()
    for finding in raw:
        for key in ("Secret", "Match", "Line"):
            value = finding.get(key)
            if isinstance(value, str) and value and value != "[REDACTED]":
                secrets.add(value)
        safe = {
            "description": sanitize_text(finding.get("Description"), secrets),
            "path": sanitize_text(
                relative_path(str(finding.get("File") or ""), target), secrets
            ),
            "symlink_path": sanitize_text(
                relative_path(str(finding.get("SymlinkFile") or ""), target),
                secrets,
            ),
            "line_start": finding.get("StartLine"),
            "line_end": finding.get("EndLine"),
            "column_start": finding.get("StartColumn"),
            "column_end": finding.get("EndColumn"),
            "commit": str(finding.get("Commit") or ""),
            "date": str(finding.get("Date") or ""),
            "rule_id": str(finding.get("RuleID") or "unknown"),
            "fingerprint": str(finding.get("Fingerprint") or ""),
            "tags": finding.get("Tags") if isinstance(finding.get("Tags"), list) else [],
        }
        safe["in_baseline"] = bool(
            baseline_fingerprints
            and safe["fingerprint"]
            and safe["fingerprint"] in baseline_fingerprints
        )
        safe["repository_ignored"] = bool(
            repository_ignored_fingerprints
            and safe["fingerprint"]
            and safe["fingerprint"] in repository_ignored_fingerprints
        )
        retained.append(safe)
        normalized.append(
            {
                "source": "Gitleaks",
                "scan": source_name,
                "rule_id": safe["rule_id"],
                "scanner_severity": "UNKNOWN",
                "report_severity": "Unassigned",
                "triage_status": "Needs human review",
                "confidence": "Low",
                "path": safe["path"],
                "line_start": safe["line_start"],
                "line_end": safe["line_end"],
                "message": safe["description"],
                "commits": [safe["commit"]] if safe["commit"] else [],
                "fingerprint": safe["fingerprint"],
                "in_baseline": safe["in_baseline"],
                "repository_ignored": safe["repository_ignored"],
                "evidence": [],
                "impact": "",
                "remediation": "",
            }
        )
    return retained, normalized, secrets


def severity_from_osv(vulnerability: Dict[str, Any]) -> str:
    database = vulnerability.get("database_specific") or {}
    severity = str(database.get("severity") or "").upper()
    if severity in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
        return "Medium" if severity == "MODERATE" else severity.title()
    return "Unassigned"


def sanitize_osv(raw: Any, target: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not isinstance(raw, dict) or not isinstance(raw.get("results", []), list):
        raise AuditError("OSV-Scanner output has an unexpected JSON shape")
    retained_results: List[Dict[str, Any]] = []
    normalized: List[Dict[str, Any]] = []
    for result in raw.get("results", []):
        source = result.get("source") or {}
        source_path = sanitize_text(
            relative_path(str(source.get("path") or ""), target)
        )
        packages = []
        for package_entry in result.get("packages", []):
            package = package_entry.get("package") or {}
            vulnerabilities = package_entry.get("vulnerabilities") or []
            safe_vulnerabilities = []
            seen_ids: Set[str] = set()
            for vulnerability in vulnerabilities:
                vulnerability_id = str(vulnerability.get("id") or "unknown")
                if vulnerability_id in seen_ids:
                    continue
                seen_ids.add(vulnerability_id)
                safe_vulnerability = {
                    "id": vulnerability_id,
                    "aliases": sorted(str(item) for item in vulnerability.get("aliases", [])),
                    "summary": sanitize_text(vulnerability.get("summary")),
                    "severity": severity_from_osv(vulnerability),
                    "modified": str(vulnerability.get("modified") or ""),
                }
                safe_vulnerabilities.append(safe_vulnerability)
                normalized.append(
                    {
                        "source": "OSV-Scanner",
                        "rule_id": vulnerability_id,
                        "scanner_severity": safe_vulnerability["severity"],
                        "report_severity": safe_vulnerability["severity"],
                        "triage_status": "Needs human review",
                        "confidence": "Medium",
                        "path": source_path,
                        "line_start": None,
                        "line_end": None,
                        "message": (
                            f"{package.get('name', 'unknown')} "
                            f"{package.get('version', 'unknown')}: "
                            f"{safe_vulnerability['summary']}"
                        ).strip(),
                        "commits": [],
                        "fingerprint": (
                            f"{source_path}:{package.get('ecosystem', '')}:"
                            f"{package.get('name', '')}:{package.get('version', '')}:"
                            f"{vulnerability_id}"
                        ),
                        "evidence": [],
                        "impact": "",
                        "remediation": "",
                    }
                )
            packages.append(
                {
                    "name": str(package.get("name") or ""),
                    "version": str(package.get("version") or ""),
                    "ecosystem": str(package.get("ecosystem") or ""),
                    "vulnerabilities": safe_vulnerabilities,
                }
            )
        retained_results.append(
            {
                "source": {"path": source_path, "type": str(source.get("type") or "")},
                "packages": packages,
            }
        )
    return {"results": retained_results}, normalized


def deduplicate_findings(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for finding in findings:
        source = finding["source"]
        if source == "Gitleaks":
            key = (
                source,
                finding["rule_id"],
                finding["path"],
                finding["line_start"],
            )
        else:
            key = (
                source,
                finding["rule_id"],
                finding["path"],
                finding["line_start"],
                finding["line_end"],
                finding.get("fingerprint", ""),
            )
        if key not in groups:
            groups[key] = dict(finding)
            groups[key]["commits"] = list(finding.get("commits", []))
        else:
            groups[key]["commits"] = sorted(
                set(groups[key].get("commits", [])) | set(finding.get("commits", []))
            )

    ordered = sorted(
        groups.values(),
        key=lambda item: (
            item["source"],
            item["path"],
            item["line_start"] or 0,
            item["rule_id"],
            item.get("fingerprint", ""),
        ),
    )
    counters = {"Gitleaks": 0, "Manual": 0, "OSV-Scanner": 0, "Semgrep": 0}
    prefixes = {
        "Gitleaks": "GL",
        "Manual": "MAN",
        "OSV-Scanner": "OSV",
        "Semgrep": "SG",
    }
    for finding in ordered:
        counters[finding["source"]] += 1
        finding["id"] = f"{prefixes[finding['source']]}-{counters[finding['source']]:03d}"
    return ordered


def ensure_no_known_secret(value: Any, secrets: Iterable[str]) -> None:
    serialized = json.dumps(value, sort_keys=True)
    for secret in secrets:
        if secret and secret in serialized:
            raise AuditError("Sanitization failed: retained artifacts contain scanner secret data")


def scanner_status(
    *,
    result: Dict[str, Any],
    report_loaded: bool,
    accepted_finding_exit_codes: Set[int],
    diagnostics: str,
) -> Dict[str, Any]:
    exit_code = result.get("exit_code")
    completed = (
        not result.get("timed_out")
        and report_loaded
        and exit_code in accepted_finding_exit_codes
    )
    return {
        **result,
        "status": "completed" if completed else "failed",
        "diagnostics": sanitize_text(diagnostics)[-4000:],
    }


def resolve_optional_path(value: Optional[str], target: Path) -> Optional[Path]:
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = target / path
    return path.resolve()


def registry_config(config: str, target: Path) -> bool:
    local = resolve_optional_path(config, target)
    if local and local.exists():
        return False
    return (
        config == "auto"
        or config.startswith(("p/", "r/", "https://", "http://"))
    )


def run_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        raise AuditError(f"Target is not a directory: {target}")

    if args.artifact_root:
        requested_artifact_root = Path(args.artifact_root).expanduser()
        if not requested_artifact_root.is_absolute():
            requested_artifact_root = target / requested_artifact_root
    else:
        requested_artifact_root = target / ".security-audit"
    if requested_artifact_root.is_symlink():
        raise AuditError("Artifact root must not be a symlink")
    artifact_root = requested_artifact_root.resolve()
    if not args.artifact_root and not path_is_within(artifact_root, target):
        raise AuditError("Default artifact root resolves outside the target")

    for control_name in (
        ".gitleaks.toml",
        ".gitleaksignore",
        ".gitignore",
        ".semgrepignore",
        "osv-scanner.toml",
    ):
        control_path = target / control_name
        if control_path.is_symlink() and not path_is_within(control_path, target):
            raise AuditError(
                f"Scanner control file resolves outside the target: {control_name}"
            )

    artifact_root_created = not artifact_root.exists()
    artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not artifact_root.is_dir():
        raise AuditError(f"Artifact root is not a directory: {artifact_root}")
    if artifact_root_created:
        os.chmod(artifact_root, 0o700)
    artifact_ignore = artifact_root / ".gitignore"
    if not artifact_ignore.exists():
        atomic_write_text(artifact_ignore, "*\n")

    run_id = args.run_id or utc_run_id()
    run_dir = artifact_root / "runs" / run_id
    if run_dir.exists():
        raise AuditError(f"Run directory already exists: {run_dir}")
    for directory in ("config", "scanner", "normalized"):
        (run_dir / directory).mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(run_dir, 0o700)
    for directory in ("config", "scanner", "normalized"):
        os.chmod(run_dir / directory, 0o700)

    files, scanner_excludes, escaping_symlinks, lockfiles = discover_files(
        target, artifact_root
    )
    file_coverage = {
        "target": str(target),
        "eligible_count": sum(1 for item in files if item["eligible"]),
        "files": files,
    }
    atomic_write_json(run_dir / "normalized" / "file-coverage.json", file_coverage)

    base_gitleaks = resolve_optional_path(args.gitleaks_config, target)
    if base_gitleaks is None:
        repository_config = target / ".gitleaks.toml"
        base_gitleaks = repository_config if repository_config.exists() else None
    effective_gitleaks = build_gitleaks_config(
        target, run_dir, base_gitleaks, scanner_excludes
    )
    osv_config = run_dir / "config" / "osv-scanner.toml"
    atomic_write_text(
        osv_config,
        "# Audit-local empty configuration; repository ignores are not applied.\n",
    )

    repository_ignore_path = target / ".gitleaksignore"
    repository_ignored_fingerprints: Set[str] = set()
    if repository_ignore_path.is_file():
        try:
            repository_ignored_fingerprints = {
                line.strip()
                for line in repository_ignore_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
        except OSError as error:
            raise AuditError(
                f"Cannot read repository Gitleaks ignore file: {error}"
            ) from error
    ignore_path = run_dir / "config" / ".gitleaksignore"
    atomic_write_text(ignore_path, "")

    metadata: Dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": str(target),
        "artifact_root": str(artifact_root),
        "mode": args.mode,
        "network_authorized": bool(args.allow_network),
        "registry_project_url_disclosure_accepted": bool(args.allow_registry),
        "escaping_symlinks": escaping_symlinks,
        "scanner_excludes": scanner_excludes,
        "supported_lockfiles": lockfiles,
        "gitleaks_baseline": None,
        "repository_gitleaks_ignore": {
            "path": str(repository_ignore_path)
            if repository_ignore_path.is_file()
            else None,
            "fingerprint_count": len(repository_ignored_fingerprints),
            "behavior": "annotation_only",
        },
        "scanners": {},
        "limitations": [],
    }
    all_findings: List[Dict[str, Any]] = []
    known_secrets: Set[str] = set()
    baseline_fingerprints: Set[str] = set()
    if args.baseline:
        baseline_path = resolve_optional_path(args.baseline, target)
        if baseline_path is None:
            raise AuditError("Gitleaks baseline path could not be resolved")
        baseline = load_json(baseline_path)
        if not isinstance(baseline, list):
            raise AuditError("Gitleaks baseline must be a JSON array")
        baseline_fingerprints = {
            str(item.get("Fingerprint"))
            for item in baseline
            if isinstance(item, dict) and item.get("Fingerprint")
        }
        metadata["gitleaks_baseline"] = {
            "path": str(baseline_path),
            "fingerprint_count": len(baseline_fingerprints),
            "behavior": "annotation_only",
        }

    with tempfile.TemporaryDirectory(prefix="repository-security-audit-") as temporary:
        temporary_path = Path(temporary).resolve()
        if path_is_within(temporary_path, target):
            raise AuditError(
                "System temporary directory resolves inside the audit target"
            )
        os.chmod(temporary_path, 0o700)
        environment = private_environment(temporary_path)

        semgrep = shutil.which("semgrep")
        if not semgrep:
            metadata["scanners"]["semgrep"] = {
                "status": "unavailable",
                "version": None,
            }
            metadata["limitations"].append("Semgrep is unavailable.")
        elif registry_config(args.semgrep_config, target) and not args.allow_registry:
            metadata["scanners"]["semgrep"] = {
                "status": "blocked",
                "version": tool_version(
                    semgrep,
                    ["scan", "--disable-version-check", "--version"],
                    target,
                    env=environment,
                ),
            }
            metadata["limitations"].append(
                "Semgrep registry access and project URL disclosure were not authorized."
            )
        else:
            raw_semgrep = temporary_path / "semgrep.json"
            command = [
                semgrep,
                "scan",
                "--config",
                args.semgrep_config,
                "--metrics=off",
                "--disable-version-check",
                "--oss-only",
                "--no-secrets-validation",
                "--no-git-ignore",
                "--disable-nosem",
                "--json",
                "--output",
                str(raw_semgrep),
            ]
            for excluded in scanner_excludes:
                command.extend(["--exclude", excluded])
            command.append(str(target))
            result, stdout, stderr = command_result(
                command, cwd=target, timeout=args.timeout, env=environment
            )
            loaded = False
            try:
                raw = read_optional_report(
                    raw_semgrep, successful_empty=result["exit_code"] == 0
                )
                safe_report, normalized = sanitize_semgrep(raw, target)
                atomic_write_json(run_dir / "scanner" / "semgrep.json", safe_report)
                all_findings.extend(normalized)
                add_scanner_coverage(
                    files, safe_report["paths"]["scanned"], "Semgrep"
                )
                loaded = True
            except AuditError as error:
                stderr += f"\n{error}"
            status = scanner_status(
                result=result,
                report_loaded=loaded,
                accepted_finding_exit_codes={0},
                diagnostics=stderr or stdout,
            )
            status["version"] = tool_version(
                semgrep,
                ["scan", "--disable-version-check", "--version"],
                target,
                env=environment,
            )
            metadata["scanners"]["semgrep"] = status
            if status["status"] != "completed":
                metadata["limitations"].append("Semgrep did not complete successfully.")
            elif load_json(run_dir / "scanner" / "semgrep.json").get("errors"):
                metadata["limitations"].append(
                    "Semgrep reported parse or scan errors; affected paths require review."
                )

        gitleaks = shutil.which("gitleaks")
        if not gitleaks:
            metadata["scanners"]["gitleaks_dir"] = {
                "status": "unavailable",
                "version": None,
            }
            if args.mode == "full":
                metadata["scanners"]["gitleaks_git"] = {
                    "status": "unavailable",
                    "version": None,
                }
            metadata["limitations"].append("Gitleaks is unavailable.")
        else:
            gitleaks_version = tool_version(
                gitleaks, ["version"], target, env=environment
            )
            scans = [("gitleaks_dir", "dir")]
            git_available = (target / ".git").exists() or subprocess.run(
                ["git", "-C", str(target), "rev-parse", "--is-inside-work-tree"],
                check=False,
                capture_output=True,
                text=True,
            ).returncode == 0
            if args.mode == "full" and git_available:
                scans.append(("gitleaks_git", "git"))
            elif args.mode == "full":
                metadata["scanners"]["gitleaks_git"] = {
                    "status": "not_applicable",
                    "version": gitleaks_version,
                }
                metadata["limitations"].append(
                    "Git history was requested but the target is not a Git work tree."
                )

            for scanner_name, subcommand in scans:
                raw_gitleaks = temporary_path / f"{scanner_name}.json"
                command = [
                    gitleaks,
                    subcommand,
                    str(target),
                    "--config",
                    str(effective_gitleaks),
                    "--gitleaks-ignore-path",
                    str(ignore_path),
                    "--redact=100",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(raw_gitleaks),
                    "--timeout",
                    str(args.timeout),
                    "--no-banner",
                    "--no-color",
                    "--ignore-gitleaks-allow",
                ]
                result, stdout, stderr = command_result(
                    command, cwd=target, timeout=args.timeout + 30, env=environment
                )
                loaded = False
                try:
                    raw = read_optional_report(
                        raw_gitleaks, successful_empty=result["exit_code"] == 0
                    )
                    safe_report, normalized, secrets = sanitize_gitleaks(
                        raw,
                        target,
                        scanner_name,
                        baseline_fingerprints=baseline_fingerprints,
                        repository_ignored_fingerprints=repository_ignored_fingerprints,
                    )
                    known_secrets.update(secrets)
                    atomic_write_json(
                        run_dir / "scanner" / f"{scanner_name}.json", safe_report
                    )
                    all_findings.extend(normalized)
                    loaded = True
                except AuditError as error:
                    stderr += f"\n{error}"
                status = scanner_status(
                    result=result,
                    report_loaded=loaded,
                    accepted_finding_exit_codes={0, 1},
                    diagnostics=sanitize_text(stderr or stdout, known_secrets),
                )
                status["version"] = gitleaks_version
                metadata["scanners"][scanner_name] = status
                if status["status"] != "completed":
                    metadata["limitations"].append(
                        f"{scanner_name} did not complete successfully."
                    )
                elif scanner_name == "gitleaks_dir":
                    add_scanner_coverage(
                        files,
                        (
                            item["path"]
                            for item in files
                            if item.get("eligible")
                        ),
                        "Gitleaks",
                    )

        if not lockfiles:
            metadata["scanners"]["osv"] = {
                "status": "not_applicable",
                "version": None,
            }
        else:
            osv = shutil.which("osv-scanner")
            if not osv:
                metadata["scanners"]["osv"] = {
                    "status": "unavailable",
                    "version": None,
                }
                metadata["limitations"].append(
                    "OSV-Scanner is unavailable although supported lockfiles exist."
                )
            elif not args.allow_network:
                metadata["scanners"]["osv"] = {
                    "status": "blocked",
                    "version": tool_version(
                        osv, ["--version"], target, env=environment
                    ),
                }
                metadata["limitations"].append(
                    "OSV advisory database access was not authorized."
                )
            else:
                raw_osv = temporary_path / "osv.json"
                command = [
                    osv,
                    "scan",
                    "--format",
                    "json",
                    "--config",
                    str(osv_config),
                ]
                for lockfile in lockfiles:
                    command.extend(["--lockfile", str(target / lockfile)])
                result, stdout, stderr = command_result(
                    command,
                    cwd=target,
                    timeout=args.timeout,
                    env=environment,
                    stdout_path=raw_osv,
                )
                loaded = False
                try:
                    raw = read_optional_report(raw_osv)
                    safe_report, normalized = sanitize_osv(raw, target)
                    atomic_write_json(run_dir / "scanner" / "osv.json", safe_report)
                    all_findings.extend(normalized)
                    add_scanner_coverage(
                        files,
                        (
                            result["source"]["path"]
                            for result in safe_report["results"]
                        ),
                        "OSV-Scanner",
                    )
                    loaded = True
                except AuditError as error:
                    stderr += f"\n{error}"
                status = scanner_status(
                    result=result,
                    report_loaded=loaded,
                    accepted_finding_exit_codes={0, 1},
                    diagnostics=stderr,
                )
                status["version"] = tool_version(
                    osv, ["--version"], target, env=environment
                )
                metadata["scanners"]["osv"] = status
                if status["status"] != "completed":
                    metadata["limitations"].append(
                        "OSV-Scanner did not complete successfully."
                    )

    findings = deduplicate_findings(all_findings)
    ensure_no_known_secret(findings, known_secrets)
    atomic_write_json(
        run_dir / "normalized" / "findings.json",
        {"schema_version": 1, "findings": findings},
    )
    atomic_write_json(
        run_dir / "normalized" / "file-coverage.json", file_coverage
    )
    metadata["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    metadata["limitations"] = sorted(set(metadata["limitations"]))
    atomic_write_json(run_dir / "run-metadata.json", metadata)
    ensure_no_known_secret(load_json(run_dir / "run-metadata.json"), known_secrets)

    summary = {
        "run_dir": str(run_dir),
        "finding_count": len(findings),
        "limitations": metadata["limitations"],
    }
    print(json.dumps(summary, indent=2))
    return 0 if not metadata["limitations"] else 3


def canonical_asvs_id(source_id: str) -> str:
    identifier = source_id[1:] if source_id.startswith("V") else source_id
    return f"v5.0.0-{identifier}"


def init_controls(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser().resolve()
    controls: List[Dict[str, Any]] = []
    if args.profile == "web":
        actual_checksum = sha256_file(ASVS_PATH)
        if actual_checksum != ASVS_SHA256:
            raise AuditError(
                "Bundled ASVS data failed checksum verification: "
                f"expected {ASVS_SHA256}, got {actual_checksum}"
            )
        raw = load_json(ASVS_PATH)
        requirements = raw.get("requirements", [])
        for requirement in requirements:
            level = int(requirement["L"])
            if level > args.level:
                continue
            controls.append(
                {
                    "id": canonical_asvs_id(str(requirement["req_id"])),
                    "source_id": str(requirement["req_id"]),
                    "framework": "OWASP ASVS",
                    "version": "5.0.0",
                    "level": level,
                    "chapter": str(requirement["chapter_name"]),
                    "section": str(requirement["section_name"]),
                    "requirement": str(requirement["req_description"]),
                    "state": "Unknown",
                    "confidence": "Low",
                    "evidence": [],
                    "rationale": "",
                    "owasp_categories": [],
                }
            )
        framework = {"name": "OWASP ASVS", "version": "5.0.0", "level": args.level}
    else:
        raw = load_json(GENERIC_CONTROLS_PATH)
        for control in raw["controls"]:
            controls.append(
                {
                    **control,
                    "state": "Unknown",
                    "confidence": "Low",
                    "evidence": [],
                    "rationale": "",
                }
            )
        framework = {
            "name": "Repository Security Audit Baseline",
            "version": str(raw["version"]),
            "level": None,
        }
    document = {
        "schema_version": 1,
        "profile": args.profile,
        "framework": framework,
        "controls": controls,
    }
    atomic_write_json(output, document)
    print(f"Wrote {len(controls)} controls to {output}")
    return 0


def validate_controls(document: Any) -> List[Dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("controls"), list):
        raise AuditError("controls.json must contain a controls array")
    seen: Set[str] = set()
    for control in document["controls"]:
        identifier = str(control.get("id") or "")
        if not identifier or identifier in seen:
            raise AuditError(f"Control ID is missing or duplicated: {identifier!r}")
        seen.add(identifier)
        for field in ("framework", "requirement"):
            if not isinstance(control.get(field), str) or not control[field].strip():
                raise AuditError(f"{identifier}: {field} is required")
        if control.get("state") not in CONTROL_STATES:
            raise AuditError(f"{identifier}: invalid control state")
        if control.get("confidence") not in CONFIDENCES:
            raise AuditError(f"{identifier}: invalid confidence")
        evidence = control.get("evidence")
        if not isinstance(evidence, list):
            raise AuditError(f"{identifier}: evidence must be an array")
        if not isinstance(control.get("owasp_categories"), list):
            raise AuditError(f"{identifier}: owasp_categories must be an array")
        for category in control["owasp_categories"]:
            if not re.fullmatch(r"A(?:0[1-9]|10)", str(category)):
                raise AuditError(f"{identifier}: invalid OWASP category {category!r}")
        if control["state"] in {"Verified", "Partial"} and not evidence:
            raise AuditError(f"{identifier}: {control['state']} requires evidence")
        if control["state"] in {"Missing", "Not applicable"} and not str(
            control.get("rationale") or ""
        ).strip():
            raise AuditError(f"{identifier}: {control['state']} requires rationale")
    return document["controls"]


def validate_file_coverage(document: Any) -> List[Dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise AuditError("file-coverage.json must contain a files array")
    seen: Set[str] = set()
    for file_record in document["files"]:
        path = str(file_record.get("path") or "")
        if not path or path in seen:
            raise AuditError(f"File path is missing or duplicated: {path!r}")
        seen.add(path)
        if file_record.get("eligible"):
            if file_record.get("manual_status") not in FILE_STATUSES:
                raise AuditError(f"{path}: invalid manual_status")
        elif not file_record.get("exclusion_reason"):
            raise AuditError(f"{path}: excluded files require a reason")
        if not isinstance(file_record.get("scanner_coverage"), list):
            raise AuditError(f"{path}: scanner_coverage must be an array")
        for scanner in file_record["scanner_coverage"]:
            if scanner not in {"Semgrep", "Gitleaks", "OSV-Scanner"}:
                raise AuditError(f"{path}: invalid scanner coverage {scanner!r}")
    return document["files"]


def validate_findings(document: Any, final: bool = False) -> List[Dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise AuditError("findings.json must contain a findings array")
    seen: Set[str] = set()
    for finding in document["findings"]:
        identifier = str(finding.get("id") or "")
        if not identifier or identifier in seen:
            raise AuditError(f"Finding ID is missing or duplicated: {identifier!r}")
        seen.add(identifier)
        if finding.get("source") not in FINDING_SOURCES:
            raise AuditError(f"{identifier}: invalid finding source")
        expected_prefix = {
            "Semgrep": "SG",
            "Gitleaks": "GL",
            "OSV-Scanner": "OSV",
            "Manual": "MAN",
        }[finding["source"]]
        if not re.fullmatch(rf"{expected_prefix}-[0-9]{{3,}}", identifier):
            raise AuditError(
                f"{identifier}: ID prefix does not match {finding['source']}"
            )
        for field in ("rule_id", "path", "message"):
            if not isinstance(finding.get(field), str):
                raise AuditError(f"{identifier}: {field} must be a string")
        if not isinstance(finding.get("scanner_severity"), str):
            raise AuditError(f"{identifier}: scanner_severity must be a string")
        for field in ("line_start", "line_end"):
            if finding.get(field) is not None and not isinstance(
                finding.get(field), int
            ):
                raise AuditError(f"{identifier}: {field} must be an integer or null")
        for field in ("commits", "evidence"):
            if not isinstance(finding.get(field), list):
                raise AuditError(f"{identifier}: {field} must be an array")
        for field in ("impact", "remediation"):
            if not isinstance(finding.get(field), str):
                raise AuditError(f"{identifier}: {field} must be a string")
        if finding.get("triage_status") not in TRIAGE_STATUSES:
            raise AuditError(f"{identifier}: invalid triage_status")
        if finding.get("confidence") not in CONFIDENCES:
            raise AuditError(f"{identifier}: invalid confidence")
        if finding.get("report_severity") not in REPORT_SEVERITIES:
            raise AuditError(f"{identifier}: invalid report_severity")
        if (
            final
            and finding.get("report_severity") == "Unassigned"
            and finding.get("triage_status") != "Likely false positive"
        ):
            raise AuditError(f"{identifier}: report severity is still unassigned")
        if final and finding.get("triage_status") != "Likely false positive":
            for field in ("evidence", "impact", "remediation"):
                if not finding.get(field):
                    raise AuditError(f"{identifier}: final finding requires {field}")
    return document["findings"]


def validate_metadata(document: Any) -> Dict[str, Any]:
    if not isinstance(document, dict):
        raise AuditError("run-metadata.json must contain an object")
    if not isinstance(document.get("scanners"), dict):
        raise AuditError("run-metadata.json must contain a scanners object")
    if not isinstance(document.get("limitations"), list):
        raise AuditError("run-metadata.json must contain a limitations array")
    return document


def percentage(numerator: int, denominator: int) -> Optional[float]:
    if denominator == 0:
        return None
    return round(numerator / denominator * 100, 1)


def calculate_coverage(
    controls_document: Any,
    files_document: Any,
    findings_document: Any,
    metadata: Any,
) -> Dict[str, Any]:
    metadata = validate_metadata(metadata)
    controls = validate_controls(controls_document)
    files = validate_file_coverage(files_document)
    findings = validate_findings(findings_document)

    counts = {state: 0 for state in CONTROL_STATES}
    for control in controls:
        counts[control["state"]] += 1
    applicable = (
        counts["Verified"]
        + counts["Partial"]
        + counts["Missing"]
        + counts["Unknown"]
    )
    scorable = counts["Verified"] + counts["Partial"] + counts["Missing"]
    eligible_files = [item for item in files if item.get("eligible")]
    reviewed_files = [
        item
        for item in eligible_files
        if item.get("manual_status") in {"manually_reviewed", "both"}
    ]
    actionable_findings = [
        item
        for item in findings
        if item.get("triage_status") in {"Confirmed", "Likely true positive"}
    ]
    unresolved_findings = [
        item
        for item in findings
        if item.get("triage_status") == "Needs human review"
        or (
            item.get("report_severity") == "Unassigned"
            and item.get("triage_status") != "Likely false positive"
        )
    ]

    scanner_incomplete = []
    for name, scanner in (metadata.get("scanners") or {}).items():
        if scanner.get("status") not in {"completed", "not_applicable"}:
            scanner_incomplete.append(name)
    incomplete = bool(
        counts["Unknown"]
        or len(reviewed_files) != len(eligible_files)
        or scanner_incomplete
        or metadata.get("limitations")
        or unresolved_findings
    )
    action_required = bool(
        counts["Partial"] or counts["Missing"] or actionable_findings
    )
    disposition = (
        "Findings require action"
        if action_required
        else ("Undetermined" if incomplete else "Pass")
    )
    return {
        "schema_version": 1,
        "completion": "Incomplete" if incomplete else "Complete",
        "disposition": disposition,
        "controls": {
            "verified": counts["Verified"],
            "partial": counts["Partial"],
            "missing": counts["Missing"],
            "unknown": counts["Unknown"],
            "not_applicable": counts["Not applicable"],
            "applicable": applicable,
            "scorable": scorable,
            "verified_control_coverage_percent": percentage(
                counts["Verified"], scorable
            ),
            "implementation_present_percent": percentage(
                counts["Verified"] + counts["Partial"], scorable
            ),
            "evidence_completeness_percent": percentage(scorable, applicable),
        },
        "files": {
            "reviewed": len(reviewed_files),
            "eligible": len(eligible_files),
            "manual_review_coverage_percent": percentage(
                len(reviewed_files), len(eligible_files)
            ),
        },
        "findings": {
            "total": len(findings),
            "actionable": len(actionable_findings),
            "unresolved": len(unresolved_findings),
        },
        "incomplete_scanners": sorted(scanner_incomplete),
    }


def coverage_command(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser().resolve()
    result = calculate_coverage(
        load_json(Path(args.controls).expanduser().resolve()),
        load_json(Path(args.files).expanduser().resolve()),
        load_json(Path(args.findings).expanduser().resolve()),
        load_json(Path(args.metadata).expanduser().resolve()),
    )
    atomic_write_json(output, result)
    print(json.dumps(result, indent=2))
    return 0


def find_forbidden_data(value: Any, path: str = "$") -> List[str]:
    forbidden_keys = {
        "Secret",
        "Match",
        "Line",
        "Author",
        "Email",
        "metavars",
        "lines",
        "abstract_content",
    }
    problems: List[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in forbidden_keys:
                problems.append(f"forbidden raw scanner field at {child_path}")
            problems.extend(find_forbidden_data(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            problems.extend(find_forbidden_data(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        for pattern in SECRET_PATTERNS:
            if pattern.search(value):
                problems.append(f"possible unredacted secret at {path}")
                break
    return problems


def gitleaks_verify_retained_artifacts(run_dir: Path) -> None:
    gitleaks = shutil.which("gitleaks")
    if not gitleaks:
        return
    with tempfile.TemporaryDirectory(
        prefix="repository-security-audit-verify-"
    ) as temporary:
        temporary_path = Path(temporary).resolve()
        if path_is_within(temporary_path, run_dir):
            raise AuditError("Verification temporary directory resolves inside the run")
        os.chmod(temporary_path, 0o700)
        config = temporary_path / "gitleaks.toml"
        ignore = temporary_path / ".gitleaksignore"
        report = temporary_path / "report.json"
        atomic_write_text(
            config,
            'title = "Audit artifact verification"\n\n[extend]\nuseDefault = true\n',
        )
        atomic_write_text(ignore, "")
        command = [
            gitleaks,
            "dir",
            str(run_dir),
            "--config",
            str(config),
            "--gitleaks-ignore-path",
            str(ignore),
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--timeout",
            "120",
            "--no-banner",
            "--no-color",
            "--ignore-gitleaks-allow",
        ]
        result, _, _ = command_result(
            command,
            cwd=run_dir,
            timeout=150,
            env=private_environment(temporary_path),
        )
        if result["timed_out"] or result["exit_code"] not in {0, 1}:
            raise AuditError("Gitleaks could not verify retained audit artifacts")
        findings = read_optional_report(
            report, successful_empty=result["exit_code"] == 0
        )
        if not isinstance(findings, list):
            raise AuditError("Gitleaks artifact-verification report is malformed")
        if findings:
            locations = sorted(
                {
                    relative_path(str(item.get("File") or ""), run_dir)
                    for item in findings
                    if isinstance(item, dict)
                }
            )
            rendered = ", ".join(locations[:10]) or "unknown retained path"
            raise AuditError(
                "Retained audit artifacts still match secret-detection rules: "
                + rendered
            )


def verify_command(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser().resolve()
    required = [
        run_dir / "run-metadata.json",
        run_dir / "normalized" / "findings.json",
        run_dir / "normalized" / "controls.json",
        run_dir / "normalized" / "file-coverage.json",
        run_dir / "normalized" / "coverage.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise AuditError("Missing required artifacts: " + ", ".join(missing))

    documents: Dict[Path, Any] = {}
    for path in sorted(run_dir.rglob("*.json")):
        documents[path] = load_json(path)
    validate_findings(
        documents[run_dir / "normalized" / "findings.json"], final=True
    )
    validate_controls(documents[run_dir / "normalized" / "controls.json"])
    validate_file_coverage(
        documents[run_dir / "normalized" / "file-coverage.json"]
    )
    expected_coverage = calculate_coverage(
        documents[run_dir / "normalized" / "controls.json"],
        documents[run_dir / "normalized" / "file-coverage.json"],
        documents[run_dir / "normalized" / "findings.json"],
        documents[run_dir / "run-metadata.json"],
    )
    actual_coverage = documents[run_dir / "normalized" / "coverage.json"]
    if expected_coverage != actual_coverage:
        raise AuditError("coverage.json does not match its source artifacts")

    problems: List[str] = []
    for path, document in documents.items():
        for problem in find_forbidden_data(document):
            problems.append(f"{path.relative_to(run_dir)}: {problem}")
    if args.report:
        report = Path(args.report).expanduser().resolve()
        text = report.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                problems.append(f"{report}: possible unredacted secret")
    if problems:
        raise AuditError("Verification failed:\n- " + "\n- ".join(problems))
    gitleaks_verify_retained_artifacts(run_dir)
    print(f"Verified sanitized audit artifacts in {run_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run and sanitize repository scanners")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--artifact-root")
    scan.add_argument("--run-id")
    scan.add_argument("--mode", choices=("full", "quick"), default="full")
    scan.add_argument("--semgrep-config", default="auto")
    scan.add_argument("--gitleaks-config")
    scan.add_argument("--baseline")
    scan.add_argument("--timeout", type=int, default=900)
    scan.add_argument(
        "--allow-registry",
        action="store_true",
        help="Allow Semgrep registry access and project URL disclosure",
    )
    scan.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow OSV advisory database access",
    )
    scan.set_defaults(function=run_scan)

    controls = subparsers.add_parser(
        "init-controls", help="Create a complete control baseline"
    )
    controls.add_argument("--profile", choices=("web", "generic"), required=True)
    controls.add_argument("--level", type=int, choices=(1, 2, 3), default=1)
    controls.add_argument("--output", required=True)
    controls.set_defaults(function=init_controls)

    coverage = subparsers.add_parser(
        "coverage", help="Validate artifacts and calculate coverage"
    )
    coverage.add_argument("--controls", required=True)
    coverage.add_argument("--files", required=True)
    coverage.add_argument("--findings", required=True)
    coverage.add_argument("--metadata", required=True)
    coverage.add_argument("--output", required=True)
    coverage.set_defaults(function=coverage_command)

    verify = subparsers.add_parser(
        "verify", help="Fail closed on incomplete or unsafe final artifacts"
    )
    verify.add_argument("--run-dir", required=True)
    verify.add_argument("--report")
    verify.set_defaults(function=verify_command)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "timeout", 1) <= 0:
        parser.error("--timeout must be positive")
    try:
        return int(args.function(args))
    except (AuditError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
