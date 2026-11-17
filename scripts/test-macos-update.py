"""Exercise the macOS update transaction with local command doubles, without root."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "src/desktop/updates"


class MacosUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ec update ' ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = self.root / "service.log"
        self.authorizations = self.root / "authorizations.log"
        self.opened = self.root / "opened.log"
        self.staged = self.root / "staged.app"
        self.destination = self.root / "installed.app"
        self.incoming = self.root / "incoming.app"
        self.backup = self.root / "backup.app"
        self.receipt = self.root / "receipt.json"
        self.job = self.root / "job"
        self.job.mkdir()
        self.make_app(self.staged, "new")
        self.make_app(self.destination, "old")
        uid = self.command("uid", 'printf "%s\\n" "${EC_TEST_UID:-501}"\n')
        self.sign = self.command("codesign", "exit 0\n")
        script = (SCRIPTS / "macos-apply.sh").read_text(encoding="utf-8")
        script = script.replace("/usr/bin/id", shlex.quote(str(uid)))
        script = script.replace("/usr/bin/ditto", "/bin/cp -R")
        script = script.replace("/usr/bin/codesign", shlex.quote(str(self.sign)))
        self.apply = self.job / "apply.sh"
        self.apply.write_text(script, encoding="utf-8")

    def command(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def make_app(self, path, version, fail=False):
        binary = path / "Contents/MacOS/easy-connect"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text(
            '#!/bin/sh\n[ "$*" = "install-service --owner 501" ] || exit 2\n'
            f'printf "%s:%s\\n" {shlex.quote(version)} "$*" >> {shlex.quote(str(self.calls))}\n'
            f"exit {1 if fail else 0}\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        (path / "version").write_text(version, encoding="utf-8")

    def run_apply(self, mode="install", root=True):
        return subprocess.run(
            ["/bin/sh", str(self.apply), str(self.staged), str(self.destination),
             str(self.incoming), str(self.backup), mode, "501"],
            env={**os.environ, "EC_TEST_UID": "0" if root else "501"},
            capture_output=True, text=True, check=False,
        )

    def lines(self, path):
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def assert_old_app(self):
        self.assertEqual((self.destination / "version").read_text(), "old")
        self.assertFalse(self.incoming.exists())
        self.assertFalse(self.backup.exists())

    def run_launcher(self, cancel=False):
        plan = {"staged": self.staged, "destination": self.destination,
                "incoming": self.incoming, "backup": self.backup,
                "fallback": self.destination, "receipt": self.receipt}
        (self.job / "plan.sh").write_text(
            "parent_pid=2147483647\nversion=9.9.9\nowner=501\n"
            + "".join(f"{key}={shlex.quote(str(value))}\n" for key, value in plan.items()),
            encoding="utf-8",
        )
        elevate = self.command(
            "osascript",
            f"echo authorization >> {shlex.quote(str(self.authorizations))}\n"
            + ("exit 1\n" if cancel else 'shift\nEC_TEST_UID=0 /bin/sh "$@"\n'),
        )
        opened = self.command("open", f'printf "%s\\n" "$*" >> {shlex.quote(str(self.opened))}\n')
        script = (SCRIPTS / "macos-launch.sh").read_text(encoding="utf-8")
        script = script.replace("/usr/bin/osascript", shlex.quote(str(elevate)))
        script = script.replace("/usr/bin/open", shlex.quote(str(opened)))
        launch = self.root / "launch.sh"
        launch.write_text(script, encoding="utf-8")
        return subprocess.run(
            ["/bin/sh", str(launch), str(self.job)],
            env={**os.environ, "EC_TEST_UID": "501"},
            capture_output=True, text=True, check=False,
        )

    def test_elevation_is_requested_before_any_files_change(self):
        self.assertEqual(self.run_apply(root=False).returncode, 77)
        self.assert_old_app()
        self.assertEqual(self.lines(self.calls), [])

    def test_app_and_helper_install_together(self):
        result = self.run_apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination / "version").read_text(), "new")
        self.assertEqual((self.backup / "version").read_text(), "old")
        self.assertEqual(self.lines(self.calls), ["new:install-service --owner 501"])

    def test_failed_helper_install_restores_both_versions(self):
        self.make_app(self.staged, "new", fail=True)
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assert_old_app()
        self.assertEqual(self.lines(self.calls), ["new:install-service --owner 501",
                                                  "old:install-service --owner 501"])

    def test_explicit_rollback_restores_the_previous_helper(self):
        self.assertEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.run_apply("rollback").returncode, 0)
        self.assert_old_app()
        self.assertEqual(self.lines(self.calls)[-1], "old:install-service --owner 501")

    def test_invalid_signature_changes_neither_app_nor_helper(self):
        self.command("codesign", "exit 1\n")
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assert_old_app()
        self.assertEqual(self.lines(self.calls), [])

    def test_normal_update_has_one_authorization_and_one_helper_install(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(self.authorizations), ["authorization"])
        self.assertEqual(self.lines(self.calls), ["new:install-service --owner 501"])
        self.assertEqual(len(self.lines(self.opened)), 1)
        self.assertTrue(json.loads(self.receipt.read_text())["success"])
        self.assertEqual((self.destination / "version").read_text(), "new")
        self.assertFalse(self.job.exists())

    def test_failed_update_rolls_back_within_the_same_authorization(self):
        self.make_app(self.staged, "new", fail=True)
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_old_app()
        self.assertEqual(self.lines(self.authorizations), ["authorization"])
        self.assertEqual(self.lines(self.calls), ["new:install-service --owner 501",
                                                  "old:install-service --owner 501"])
        self.assertFalse(json.loads(self.receipt.read_text())["success"])

    def test_cancelled_authorization_keeps_the_previous_installation(self):
        self.assertEqual(self.run_launcher(cancel=True).returncode, 0)
        self.assert_old_app()
        self.assertEqual(self.lines(self.authorizations), ["authorization"])
        self.assertEqual(self.lines(self.calls), [])
        self.assertFalse(json.loads(self.receipt.read_text())["success"])


if __name__ == "__main__":
    unittest.main()
