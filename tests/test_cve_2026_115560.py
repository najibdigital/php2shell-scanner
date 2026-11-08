#!/usr/bin/env python3
"""Unit tests for the CVE-2026-115560 exposure assessment in scanner.py.

Run: python3 -m unittest tests.test_cve_2026_115560  (from the repo root)
     or: python3 tests/test_cve_2026_115560.py

Fixtures are synthetic phpinfo()-style HTML — no network, no targets.
The assessment must never claim the runtime ini_set() precondition is
visible: it is application code and is always reported as None.
"""
import os, sys, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner  # noqa: E402

def phpinfo(handler="php", enabled="On", name="PHP_SESSION_UPLOAD_PROGRESS", version="8.5.12"):
    return f"""<html><head><title>phpinfo()</title></head><body>
    <h1>PHP Version {version}</h1>
    <table><tr><td class="e">PHP License</td></tr></table>
    <h2>Configuration</h2><h2>PHP Core</h2>
    <table>
    <tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
    <tr><td class="e">session.serialize_handler</td><td class="v">{handler}</td><td class="v">{handler}</td></tr>
    <tr><td class="e">session.upload_progress.enabled</td><td class="v">{enabled}</td><td class="v">{enabled}</td></tr>
    <tr><td class="e">session.upload_progress.name</td><td class="v">{name}</td><td class="v">{name}</td></tr>
    </table><p>Zend Engine, PHP Credits, PHP Version</p></body></html>"""

class TestParse(unittest.TestCase):
    def test_parses_all_directives(self):
        cfg = scanner.parse_phpinfo_config(phpinfo(handler="php_serialize"))
        self.assertEqual(cfg["serialize_handler"], "php_serialize")
        self.assertEqual(cfg["upload_progress_enabled"], "On")
        self.assertEqual(cfg["upload_progress_name"], "PHP_SESSION_UPLOAD_PROGRESS")

    def test_empty_body(self):
        self.assertEqual(scanner.parse_phpinfo_config(""), {})

class TestAssess(unittest.TestCase):
    def assess(self, **kw):
        return scanner.assess_115560(scanner.parse_phpinfo_config(phpinfo(**kw)), True)

    def test_config_preconditions_present(self):
        a = self.assess(handler="php_binary", enabled="On")
        self.assertEqual(a["status"], "CONFIG_PRECONDITIONS_PRESENT")
        self.assertTrue(a["preconditions"]["config_serialize_handler_nondefault"])
        self.assertTrue(a["preconditions"]["upload_progress_enabled"])
        # The runtime switch is code — never claimed observable.
        self.assertIsNone(a["preconditions"]["runtime_ini_set_switch"])
        self.assertIn("default", a["waf_name_note"].lower())

    def test_mitigated_when_upload_progress_off(self):
        a = self.assess(handler="php_serialize", enabled="Off")
        self.assertEqual(a["status"], "MITIGATED")

    def test_default_handler_not_present(self):
        a = self.assess(handler="php", enabled="On")
        self.assertEqual(a["status"], "PRECONDITIONS_NOT_PRESENT_EXTERNALLY")

    def test_custom_name_flags_waf_gap(self):
        a = self.assess(handler="php", enabled="On", name="CUSTOM_PROGRESS")
        self.assertIn("NOT covered", a["waf_name_note"])

    def test_no_phpinfo_is_unknown_not_safe(self):
        a = scanner.assess_115560({}, False)
        self.assertEqual(a["status"], "UNKNOWN")
        self.assertIn("cannot be determined", a["detail"])

if __name__ == "__main__":
    unittest.main()
