import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_tools.py"
SPEC = importlib.util.spec_from_file_location("audit_tools", SCRIPT)
audit_tools = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(audit_tools)


class AuditToolsTests(unittest.TestCase):
    @staticmethod
    def control(identifier, state, confidence="High", evidence=None, rationale=""):
        return {
            "id": identifier,
            "framework": "Test baseline",
            "requirement": f"Test requirement {identifier}",
            "state": state,
            "confidence": confidence,
            "evidence": list(evidence or []),
            "rationale": rationale,
            "owasp_categories": [],
        }

    @staticmethod
    def finding(
        identifier="SG-001",
        status="Needs human review",
        severity="Unassigned",
    ):
        return {
            "id": identifier,
            "source": "Semgrep",
            "rule_id": "test.rule",
            "scanner_severity": "ERROR",
            "report_severity": severity,
            "triage_status": status,
            "confidence": "Low",
            "path": "a.py",
            "line_start": 1,
            "line_end": 1,
            "message": "Test finding",
            "commits": [],
            "fingerprint": "fixture",
            "evidence": [],
            "impact": "",
            "remediation": "",
        }

    def test_gitleaks_sanitization_removes_raw_values(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        raw = [
            {
                "Description": "GitHub token",
                "StartLine": 4,
                "EndLine": 4,
                "File": "/repo/config.txt",
                "Secret": secret,
                "Match": f"token={secret}",
                "Line": f"token={secret}",
                "RuleID": "github-pat",
                "Fingerprint": "one",
            }
        ]
        retained, normalized, secrets = audit_tools.sanitize_gitleaks(
            raw, Path("/repo"), "gitleaks_dir"
        )
        serialized = json.dumps([retained, normalized])
        self.assertNotIn(secret, serialized)
        self.assertNotIn("Secret", serialized)
        self.assertIn(secret, secrets)
        self.assertFalse(retained[0]["in_baseline"])
        self.assertFalse(retained[0]["repository_ignored"])

    def test_semgrep_sanitization_drops_source_and_metavariables(self):
        raw = {
            "version": "1",
            "results": [
                {
                    "check_id": "python.lang.security.audit",
                    "path": "/repo/app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 20},
                    "extra": {
                        "message": "unsafe call",
                        "severity": "ERROR",
                        "lines": "password = 'secret'",
                        "metavars": {"$X": {"abstract_content": "secret"}},
                    },
                }
            ],
            "errors": [],
        }
        retained, normalized = audit_tools.sanitize_semgrep(raw, Path("/repo"))
        serialized = json.dumps([retained, normalized])
        self.assertNotIn("password = 'secret'", serialized)
        self.assertNotIn("metavars", serialized)
        self.assertEqual("app.py", retained["results"][0]["path"])

    def test_deduplication_is_stable(self):
        finding = {
            "source": "Gitleaks",
            "scan": "gitleaks_dir",
            "rule_id": "generic",
            "scanner_severity": "UNKNOWN",
            "report_severity": "Unassigned",
            "triage_status": "Needs human review",
            "confidence": "Low",
            "path": "a.txt",
            "line_start": 3,
            "line_end": 3,
            "message": "possible secret",
            "commits": [],
            "fingerprint": "current",
            "evidence": [],
            "impact": "",
            "remediation": "",
        }
        historical = dict(finding)
        historical["scan"] = "gitleaks_git"
        historical["commits"] = ["abc"]
        historical["fingerprint"] = "historical"
        result = audit_tools.deduplicate_findings([historical, finding])
        self.assertEqual(1, len(result))
        self.assertEqual("GL-001", result[0]["id"])
        self.assertEqual(["abc"], result[0]["commits"])

    def test_coverage_has_no_partial_weighting(self):
        controls = {
            "controls": [
                self.control("one", "Verified", evidence=["a:1"]),
                self.control(
                    "two", "Partial", confidence="Medium", evidence=["b:2"]
                ),
                self.control(
                    "three",
                    "Missing",
                    rationale="No enforcement point exists.",
                ),
            ]
        }
        files = {
            "files": [
                {
                    "path": "a.py",
                    "eligible": True,
                    "manual_status": "both",
                    "scanner_coverage": ["Semgrep"],
                }
            ]
        }
        findings = {"findings": []}
        metadata = {
            "scanners": {"semgrep": {"status": "completed"}},
            "limitations": [],
        }
        result = audit_tools.calculate_coverage(
            controls, files, findings, metadata
        )
        self.assertEqual(33.3, result["controls"]["verified_control_coverage_percent"])
        self.assertEqual(66.7, result["controls"]["implementation_present_percent"])
        self.assertEqual("Findings require action", result["disposition"])

    def test_unresolved_finding_keeps_completion_incomplete(self):
        controls = {
            "controls": [
                self.control("one", "Verified", evidence=["a:1"])
            ]
        }
        files = {
            "files": [
                {
                    "path": "a.py",
                    "eligible": True,
                    "manual_status": "both",
                    "scanner_coverage": ["Semgrep"],
                }
            ]
        }
        findings = {"findings": [self.finding()]}
        metadata = {
            "scanners": {"semgrep": {"status": "completed"}},
            "limitations": [],
        }
        result = audit_tools.calculate_coverage(
            controls, files, findings, metadata
        )
        self.assertEqual("Incomplete", result["completion"])
        self.assertEqual("Undetermined", result["disposition"])
        self.assertEqual(1, result["findings"]["unresolved"])

    def test_control_initialization_uses_versioned_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "controls.json"
            arguments = type(
                "Arguments",
                (),
                {"output": str(output), "profile": "web", "level": 1},
            )()
            audit_tools.init_controls(arguments)
            document = json.loads(output.read_text())
            audit_tools.validate_controls(document)
            self.assertGreater(len(document["controls"]), 50)
            self.assertTrue(document["controls"][0]["id"].startswith("v5.0.0-"))
            self.assertEqual(
                audit_tools.ASVS_SHA256,
                audit_tools.sha256_file(audit_tools.ASVS_PATH),
            )

    def test_inventory_keeps_markdown_and_excludes_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "README.md").write_text("untrusted documentation")
            artifact_root = target / ".security-audit"
            artifact_root.mkdir()
            (artifact_root / "old.json").write_text("{}")
            (target / "node_modules").mkdir()
            (target / "node_modules" / "dependency.js").write_text("vendor")
            files, excludes, escaping, _ = audit_tools.discover_files(
                target, artifact_root
            )
            paths = [item["path"] for item in files]
            self.assertIn("README.md", paths)
            self.assertNotIn(".security-audit/old.json", paths)
            self.assertNotIn("node_modules/dependency.js", paths)
            self.assertIn(".security-audit", excludes)
            self.assertIn("node_modules", excludes)
            self.assertEqual([], escaping)

    def test_final_verification_recalculates_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            normalized = run_dir / "normalized"
            normalized.mkdir()
            controls = {
                "controls": [
                    self.control(
                        "RSA-01", "Verified", evidence=["app.py:1"]
                    )
                ]
            }
            files = {
                "files": [
                    {
                        "path": "app.py",
                        "eligible": True,
                        "manual_status": "both",
                        "scanner_coverage": ["Semgrep"],
                    }
                ]
            }
            findings = {"findings": []}
            metadata = {
                "scanners": {"semgrep": {"status": "completed"}},
                "limitations": [],
            }
            coverage = audit_tools.calculate_coverage(
                controls, files, findings, metadata
            )
            for name, value in (
                ("controls.json", controls),
                ("file-coverage.json", files),
                ("findings.json", findings),
                ("coverage.json", coverage),
            ):
                (normalized / name).write_text(json.dumps(value))
            (run_dir / "run-metadata.json").write_text(json.dumps(metadata))
            arguments = type(
                "Arguments",
                (),
                {"run_dir": str(run_dir), "report": None},
            )()
            self.assertEqual(0, audit_tools.verify_command(arguments))

    def test_scan_pipeline_retains_only_sanitized_evidence(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "README.md").write_text(f"token={secret}")
            (target / "app.py").write_text("eval(user_input)")
            (target / "package-lock.json").write_text("{}")
            semgrep_config = target / "rules.yml"
            semgrep_config.write_text("rules: []")
            artifact_root = target / ".security-audit"

            def fake_which(name):
                return f"/fake/{name}"

            def fake_command(
                command, *, cwd, timeout, env=None, stdout_path=None
            ):
                if command[0].endswith("semgrep"):
                    self.assertIn("--no-git-ignore", command)
                    self.assertIn("--disable-nosem", command)
                    output = Path(command[command.index("--output") + 1])
                    output.write_text(
                        json.dumps(
                            {
                                "version": "test",
                                "results": [
                                    {
                                        "check_id": "test.eval",
                                        "path": str(target / "app.py"),
                                        "start": {"line": 1, "col": 1},
                                        "end": {"line": 1, "col": 16},
                                        "extra": {
                                            "message": f"matched {secret}",
                                            "severity": "ERROR",
                                            "lines": f"token={secret}",
                                            "metavars": {
                                                "$X": {"abstract_content": secret}
                                            },
                                        },
                                    }
                                ],
                                "errors": [],
                            }
                        )
                    )
                    return (
                        {
                            "command": list(command),
                            "duration_seconds": 0.1,
                            "exit_code": 0,
                            "timed_out": False,
                        },
                        "",
                        "",
                    )
                if command[0].endswith("gitleaks"):
                    self.assertIn("--ignore-gitleaks-allow", command)
                    output = Path(command[command.index("--report-path") + 1])
                    output.write_text(
                        json.dumps(
                            [
                                {
                                    "Description": "GitHub token",
                                    "StartLine": 1,
                                    "EndLine": 1,
                                    "File": str(target / "README.md"),
                                    "Secret": secret,
                                    "Match": f"token={secret}",
                                    "Line": f"token={secret}",
                                    "RuleID": "github-pat",
                                    "Fingerprint": "fixture",
                                }
                            ]
                        )
                    )
                    return (
                        {
                            "command": list(command),
                            "duration_seconds": 0.1,
                            "exit_code": 1,
                            "timed_out": False,
                        },
                        "",
                        "",
                    )
                if command[0].endswith("osv-scanner"):
                    self.assertIn("--lockfile", command)
                    self.assertNotIn("-r", command)
                    output = {
                        "results": [
                            {
                                "source": {
                                    "path": str(target / "package-lock.json"),
                                    "type": "lockfile",
                                },
                                "packages": [
                                    {
                                        "package": {
                                            "name": "example",
                                            "version": "1.0.0",
                                            "ecosystem": "npm",
                                        },
                                        "vulnerabilities": [
                                            {
                                                "id": "GHSA-test",
                                                "summary": "Fixture advisory",
                                                "database_specific": {
                                                    "severity": "HIGH"
                                                },
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                    if stdout_path is not None:
                        Path(stdout_path).write_text(json.dumps(output))
                        rendered_output = ""
                    else:
                        rendered_output = json.dumps(output)
                    return (
                        {
                            "command": list(command),
                            "duration_seconds": 0.1,
                            "exit_code": 1,
                            "timed_out": False,
                        },
                        rendered_output,
                        "",
                    )
                self.fail(f"Unexpected command: {command}")

            arguments = type(
                "Arguments",
                (),
                {
                    "target": str(target),
                    "artifact_root": str(artifact_root),
                    "run_id": "fixture",
                    "mode": "quick",
                    "semgrep_config": str(semgrep_config),
                    "gitleaks_config": None,
                    "baseline": None,
                    "timeout": 30,
                    "provision": "never",
                    "semgrep_image": audit_tools.SEMGREP_IMAGE,
                    "gitleaks_image": audit_tools.GITLEAKS_IMAGE,
                    "allow_registry": False,
                    "allow_network": True,
                },
            )()
            with mock.patch.object(
                audit_tools.shutil, "which", side_effect=fake_which
            ), mock.patch.object(
                audit_tools, "command_result", side_effect=fake_command
            ), mock.patch.object(
                audit_tools, "tool_version", return_value="test"
            ):
                self.assertEqual(0, audit_tools.run_scan(arguments))

            run_dir = artifact_root / "runs" / "fixture"
            retained = "\n".join(
                path.read_text()
                for path in run_dir.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(secret, retained)
            findings = json.loads(
                (run_dir / "normalized" / "findings.json").read_text()
            )
            self.assertEqual(3, len(findings["findings"]))
            coverage = json.loads(
                (run_dir / "normalized" / "file-coverage.json").read_text()
            )
            self.assertIn(
                "README.md", [item["path"] for item in coverage["files"]]
            )
            self.assertIn(
                r"\\.security\\-audit",
                (run_dir / "config" / "gitleaks.toml").read_text(),
            )

    def test_container_runner_uses_read_only_source_and_private_output(self):
        runner = {
            "kind": "docker",
            "executable": "docker",
            "image": audit_tools.SEMGREP_IMAGE,
            "tool": "semgrep",
            "method": "pulled-container",
        }
        target = Path("/workspace/repository")
        run_dir = target / ".security-audit" / "runs" / "test"
        temporary = Path("/private/tmp/repository-security-audit")
        command = audit_tools.scanner_command(
            runner,
            [
                "scan",
                "--config",
                "rules.yml",
                "--output",
                str(temporary / "semgrep.json"),
                str(target),
            ],
            target=target,
            run_dir=run_dir,
            temporary_path=temporary,
            allow_network=False,
        )
        self.assertIn("--network=none", command)
        self.assertIn("type=bind,source=/workspace/repository,target=/src,readonly", command)
        self.assertIn(
            "type=bind,source=/private/tmp/repository-security-audit,target=/raw",
            command,
        )
        self.assertIn("/raw/semgrep.json", command)
        self.assertIn("/src", command)
        self.assertEqual("semgrep", command[command.index(audit_tools.SEMGREP_IMAGE) + 1])

    def test_container_paths_are_normalized_to_repository_relative_paths(self):
        raw = {
            "version": "test",
            "results": [
                {
                    "check_id": "test.rule",
                    "path": "/src/app.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"severity": "ERROR"},
                }
            ],
            "errors": [],
            "paths": {"scanned": ["/src/app.py"], "skipped": []},
        }
        retained, _ = audit_tools.sanitize_semgrep(
            raw,
            Path("/host/repository"),
            (Path("/src"),),
        )
        self.assertEqual("app.py", retained["results"][0]["path"])
        self.assertEqual(["app.py"], retained["paths"]["scanned"])

    def test_missing_scanner_is_provisioned_without_a_global_install(self):
        attempts = []
        expected = {
            "kind": "native",
            "executable": "/private/tmp/semgrep-venv/bin/semgrep",
            "method": "isolated-python",
        }
        with mock.patch.object(audit_tools, "native_runner", return_value=None), mock.patch.object(
            audit_tools,
            "provision_semgrep_native",
            return_value=dict(expected),
        ) as provision:
            runner = audit_tools.resolve_scanner_runner(
                "semgrep",
                image=audit_tools.SEMGREP_IMAGE,
                target=Path("/repo"),
                provision_root=Path("/private/tmp"),
                environment={},
                docker=None,
                provision="auto",
                attempts=attempts,
            )
        provision.assert_called_once()
        self.assertEqual("isolated-python", runner["method"])
        self.assertEqual("semgrep", runner["tool"])

    @unittest.skipUnless(shutil.which("gitleaks"), "Gitleaks is not installed")
    def test_current_gitleaks_accepts_effective_exclusion_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            run_dir = target / ".security-audit" / "runs" / "fixture"
            (run_dir / "config").mkdir(parents=True)
            (target / "README.md").write_text("documentation")
            config = audit_tools.build_gitleaks_config(
                target,
                run_dir,
                None,
                [".security-audit"],
            )
            ignore = run_dir / "config" / ".gitleaksignore"
            ignore.write_text("")
            report = root / "report.json"
            completed = subprocess.run(
                [
                    shutil.which("gitleaks"),
                    "dir",
                    str(target),
                    "--config",
                    str(config),
                    "--gitleaks-ignore-path",
                    str(ignore),
                    "--redact=100",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                    "--no-banner",
                    "--no-color",
                    "--ignore-gitleaks-allow",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual([], json.loads(report.read_text()))

    def test_default_artifact_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            outside = root / "outside"
            target.mkdir()
            outside.mkdir()
            (target / ".security-audit").symlink_to(outside, target_is_directory=True)
            arguments = type(
                "Arguments",
                (),
                {
                    "target": str(target),
                    "artifact_root": None,
                    "run_id": "fixture",
                    "mode": "quick",
                    "semgrep_config": "auto",
                    "gitleaks_config": None,
                    "baseline": None,
                    "timeout": 30,
                    "allow_registry": False,
                    "allow_network": False,
                },
            )()
            with self.assertRaises(audit_tools.AuditError):
                audit_tools.run_scan(arguments)


if __name__ == "__main__":
    unittest.main()
