import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


def run_cli(args, cwd=None):
    cmd = [sys.executable, "-m", "credaudit"] + args
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def write_file(p: Path, content: str):
    p.write_text(content, encoding="utf-8")
    return p


def load_json_array(p: Path):
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


class TestCliScan(unittest.TestCase):
    def test_scan_ndjson_and_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # Create a guaranteed hit
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            out_dir = tmp / "out"
            nd = out_dir / "findings.ndjson"
            # --no-timestamp keeps report file deterministic (report.json)
            res = run_cli([
                "scan", "-p", str(tmp), "-o", str(out_dir), "--no-cache",
                "--ndjson-out", str(nd),
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(nd.exists() and nd.stat().st_size > 0)
            # Check first NDJSON line has required fields
            first_line = nd.read_text(encoding="utf-8").splitlines()[0]
            obj = json.loads(first_line)
            for k in ["ts", "file", "rule", "severity", "redacted", "context", "line"]:
                self.assertIn(k, obj)
            # Check JSON report
            j = out_dir / "report.json"
            self.assertTrue(j.exists(), "report.json not found")
            arr = load_json_array(j)
            self.assertTrue(any(f.get("rule") == "PasswordAssignment" for f in arr))

    def test_only_rules_filters_findings(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\napi_key=sk-abcde1234567890\n")
            out = tmp / "out"
            res = run_cli([
                "scan", "-p", str(tmp), "-o", str(out), "--no-cache",
                "--formats", "json",
                "--no-timestamp",
                "--only-rules", "PasswordAssignment"
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            self.assertTrue(arr, "no findings produced")
            self.assertTrue(all(f.get("rule") == "PasswordAssignment" for f in arr))

    def test_safe_shortcut_redacts_json_and_skips_cache(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            out = tmp / "out"
            cache = tmp / "cache.json"
            res = run_cli([
                "scan",
                str(tmp),
                "-o", str(out),
                "--cache-file", str(cache),
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            report = out / "report.json"
            self.assertTrue(report.exists(), "safe shortcut did not create report.json")
            text = report.read_text(encoding="utf-8")
            self.assertNotIn("Abcd1234", text)
            self.assertIn("A****4", text)
            self.assertFalse(cache.exists(), "safe mode should not write a raw findings cache")

    def test_safe_shortcut_fast_defaults_to_small_txt_only(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            small_txt = write_file(tmp / "small.txt", "password: Abcd1234\n")
            write_file(tmp / "secret.json", "{\"password\":\"Json1234\"}\n")
            write_file(tmp / "large.txt", ("A" * 11000) + "\npassword: Large1234\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            self.assertTrue(arr, "small .txt file should be scanned")
            files = {Path(f.get("file", "")).name for f in arr}
            self.assertIn(small_txt.name, files)
            self.assertNotIn("secret.json", files)
            self.assertNotIn("large.txt", files)

    def test_scan_command_defaults_to_safe_fast(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            small_txt = write_file(tmp / "small.txt", "password: Abcd1234\n")
            write_file(tmp / "secret.env", "password=Env1234\n")
            write_file(tmp / "large.txt", ("A" * 11000) + "\npassword: Large1234\n")
            out = tmp / "out"
            cache = tmp / "cache.json"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--cache-file", str(cache),
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            text = (out / "report.json").read_text(encoding="utf-8")
            self.assertNotIn("Abcd1234", text)
            self.assertIn("A****4", text)
            self.assertFalse(cache.exists(), "default safe mode should not write a raw findings cache")
            arr = load_json_array(out / "report.json")
            files = {Path(f.get("file", "")).name for f in arr}
            self.assertIn(small_txt.name, files)
            self.assertNotIn("secret.env", files)
            self.assertNotIn("large.txt", files)

    def test_full_raw_opt_out_uses_standard_scope_and_cache(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            write_file(tmp / "secret.env", "password=Env1234\n")
            out = tmp / "out"
            cache = tmp / "cache.json"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--cache-file", str(cache),
                "--formats", "json",
                "--no-timestamp",
                "--full",
                "--raw",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            text = (out / "report.json").read_text(encoding="utf-8")
            self.assertIn("Abcd1234", text)
            self.assertIn("Env1234", text)
            self.assertTrue(cache.exists(), "raw standard mode should write the findings cache")
            arr = load_json_array(out / "report.json")
            files = {Path(f.get("file", "")).name for f in arr}
            self.assertIn("secret.env", files)

    def test_include_glob_allows_explicit_non_default_text_extension(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secret.yaml", "password: Yaml1234\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--include-glob", "**/*.yaml",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            files = {Path(f.get("file", "")).name for f in arr}
            self.assertIn("secret.yaml", files)

    def test_overlapping_rules_are_deduplicated_by_secret_value(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Secret123!;\napi_key=sk-abcde1234567890,\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--raw",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            findings_by_line = {}
            for finding in arr:
                findings_by_line.setdefault(finding.get("line"), []).append(finding)
            self.assertEqual([f.get("rule") for f in findings_by_line.get(1, [])], ["PasswordAssignment"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(1, [])], ["Secret123!"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(2, [])], ["APIKeyGeneric"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(2, [])], ["sk-abcde1234567890"])

    def test_username_and_password_keyword_indicators_are_reported(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "indicators.txt", "username=admin\nplease rotate password soon\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            rules_by_line = {}
            for finding in arr:
                rules_by_line.setdefault(finding.get("line"), []).append(finding.get("rule"))
            self.assertEqual(rules_by_line.get(1), ["UsernameAssignment"])
            self.assertEqual(rules_by_line.get(2), ["PasswordKeyword"])

    def test_standalone_password_candidates_are_reported_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(
                tmp / "candidates.txt",
                "myo@193\nmISX%%13402\npassword: myo@193\njohn@example.com\npython-docx\nCredAudit v{VERSION}\n",
            )
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--raw",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            findings_by_line = {}
            for finding in arr:
                findings_by_line.setdefault(finding.get("line"), []).append(finding)
            self.assertEqual([f.get("rule") for f in findings_by_line.get(1, [])], ["PasswordCandidate"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(1, [])], ["myo@193"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(2, [])], ["PasswordCandidate"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(2, [])], ["mISX%%13402"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(3, [])], ["PasswordAssignment"])
            self.assertNotIn(4, findings_by_line)
            self.assertNotIn(5, findings_by_line)
            self.assertNotIn(6, findings_by_line)

    def test_username_on_line_before_password_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(
                tmp / "paired.txt",
                "admin\nmyo@193\nusername=alice\npassword: Secret123!\nthis is just text\nmISX%%13402\njohn@example.com\nmISX%%13402\n",
            )
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--raw",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            findings_by_line = {}
            for finding in arr:
                findings_by_line.setdefault(finding.get("line"), []).append(finding)
            self.assertEqual([f.get("rule") for f in findings_by_line.get(1, [])], ["UsernameNearPassword"])
            self.assertEqual([f.get("severity") for f in findings_by_line.get(1, [])], ["High"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(1, [])], ["admin"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(2, [])], ["PasswordCandidate"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(3, [])], ["UsernameNearPassword"])
            self.assertEqual([f.get("severity") for f in findings_by_line.get(3, [])], ["High"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(3, [])], ["alice"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(4, [])], ["PasswordAssignment"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(6, [])], ["PasswordCandidate"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(7, [])], ["UsernameNearPassword"])
            self.assertEqual([f.get("severity") for f in findings_by_line.get(7, [])], ["High"])
            self.assertEqual([f.get("match") for f in findings_by_line.get(7, [])], ["john@example.com"])
            self.assertEqual([f.get("rule") for f in findings_by_line.get(8, [])], ["PasswordCandidate"])

    def test_shortcut_without_formats_prints_redacted_console(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Findings (redacted)", res.stdout)
            self.assertIn("Severity Rule                     Line   File", res.stdout)
            self.assertIn("PasswordAssignment", res.stdout)
            self.assertIn("A****4", res.stdout)
            self.assertNotIn("Abcd1234", res.stdout)
            self.assertFalse((out / "report.json").exists(), "console mode should not write report.json")

    def test_formats_print_clickable_file_urls(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            out = tmp / "out"
            res = run_cli([
                str(tmp),
                "-o", str(out),
                "--formats", "html", "json",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            html_reports = list(out.glob("report_*.html"))
            json_reports = list(out.glob("report_*.json"))
            self.assertEqual(len(html_reports), 1)
            self.assertEqual(len(json_reports), 1)
            html = html_reports[0].resolve().as_uri()
            json_report = json_reports[0].resolve().as_uri()
            self.assertIn("Report URLs:", res.stdout)
            self.assertIn(f"HTML: {html}", res.stdout)
            self.assertIn(f"JSON: {json_report}", res.stdout)

    def test_html_generated_with_template(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write_file(tmp / "secrets.txt", "password: Abcd1234\n")
            out = tmp / "out"
            res = run_cli([
                "scan", "-p", str(tmp), "-o", str(out), "--no-cache",
                "--formats", "html", "--timestamp"
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            # Find any HTML report in out dir
            htmls = list(out.glob("report_*.html")) or list(out.glob("report.html"))
            self.assertTrue(htmls, "no HTML report produced")
            html = htmls[0].read_text(encoding="utf-8", errors="ignore")
            # Sanity checks for the new chrome
            self.assertIn("CredAudit Report", html)
            self.assertTrue("id=\"tbl\"" in html or "<table id=\"tbl\"" in html)

    def test_scan_har_responses(self):
        """Ensure HAR response body scanning finds secrets in JSON responses (quoted style)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            har = tmp / "traffic.har"
            har_obj = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "test", "version": "1.0"},
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://example.local/"},
                            "response": {
                                "status": 200,
                                "content": {
                                    "mimeType": "application/json",
                                    "text": "{\"password\":\"Abcd1234\"}"
                                }
                            }
                        }
                    ]
                }
            }
            har.write_text(json.dumps(har_obj), encoding="utf-8")
            out = tmp / "out"
            res = run_cli([
                "scan", "-p", str(har), "-o", str(out), "--no-cache",
                "--include-ext", ".har",
                "--har-include", "responses",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            ok = any((f.get("rule") in ("PasswordAssignment","PasswordAssignmentLoose")) for f in arr)
            self.assertTrue(ok, f"No password-like finding in HAR: {arr}")

    def test_scan_archive_zip(self):
        """Ensure ZIP archives are expanded and findings remap to 'zip!inner' paths."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            zpath = tmp / "a.zip"
            # create zip with secrets.txt
            with zipfile.ZipFile(zpath, "w") as z:
                inner_name = "secrets.txt"
                z.writestr(inner_name, "password: Abcd1234\n")
            out = tmp / "out"
            res = run_cli([
                "scan", "-p", str(zpath), "-o", str(out), "--no-cache",
                "--scan-archives", "--archive-depth", "1",
                "--include-ext", ".zip",
                "--formats", "json",
                "--no-timestamp",
            ])
            self.assertEqual(res.returncode, 0, res.stderr)
            arr = load_json_array(out / "report.json")
            self.assertTrue(arr)
            # Check alias path like a.zip!secrets.txt
            self.assertTrue(any(".zip!" in (f.get("file") or "") for f in arr))


if __name__ == "__main__":
    unittest.main()
