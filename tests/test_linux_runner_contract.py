from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REGRESSION_PATH = Path(__file__).parent / "linux" / "regression.py"
SPEC = importlib.util.spec_from_file_location("linux_regression", REGRESSION_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {REGRESSION_PATH}")
REGRESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGRESSION)


class Harness(REGRESSION.Suite):
    def __init__(self, return_codes=None):
        self.args = SimpleNamespace(
            vm_a="wgtcp-a",
            vm_b="wgtcp-b",
            vm_a_host="192.0.2.10",
            vm_b_host="192.0.2.11",
            ssh_user="ubuntu",
            known_hosts_dir=Path("/tmp/known-hosts"),
            timeout=180,
            repo="/home/ubuntu/WireguardTCP",
        )
        self.ssh = "/usr/bin/ssh"
        self.commands = []
        self.results = []
        self.current_case = "suite"
        self.infrastructure_failure = None
        self.abort_reason = None
        self.return_codes = return_codes or {}

    def command(self, argv, *, vm, label, timeout=None):
        self.commands.append((argv, vm, label, timeout))
        return subprocess.CompletedProcess(argv, self.return_codes.get(vm, 0), "", "")


class LinuxRunnerContractTests(unittest.TestCase):
    def test_preflight_details_are_linux_transport_specific(self):
        suite = Harness()

        self.assertEqual(
            suite.preflight_details(),
            {
                "repo": "/home/ubuntu/WireguardTCP",
                "ssh": "/usr/bin/ssh",
                "transport": "libvirt-ssh",
            },
        )

    def test_remote_uses_verified_ssh_and_shared_guest_helpers(self):
        suite = Harness()

        suite.remote("wgtcp-a", "guest-node.sh", "diagnose")

        argv, vm, label, timeout = suite.commands[0]
        self.assertEqual(vm, "wgtcp-a")
        self.assertEqual(label, "guest-node.sh")
        self.assertEqual(timeout, 180)
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn(
            f"UserKnownHostsFile={suite.args.known_hosts_dir / 'wgtcp-a'}",
            argv,
        )
        self.assertIn("/home/ubuntu/WireguardTCP/tests/hyperv/guest-node.sh", argv)
        self.assertIn("sudo", argv)

    def test_host_transport_preflight_probes_both_management_endpoints(self):
        suite = Harness()

        with redirect_stdout(io.StringIO()):
            self.assertTrue(suite.host_transport_preflight())

        self.assertEqual(len(suite.commands), 2)
        self.assertEqual([command[1] for command in suite.commands], ["wgtcp-a", "wgtcp-b"])
        self.assertTrue(all(command[0][-1] == "true" for command in suite.commands))
        self.assertTrue(all(command[2] == "host-transport-probe" for command in suite.commands))

    def test_ssh_transport_failure_is_reported_as_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = REGRESSION.Suite.__new__(REGRESSION.Suite)
            suite.args = SimpleNamespace(timeout=180)
            suite.results_dir = Path(directory)
            suite.log_dir = suite.results_dir / "logs"
            suite.log_dir.mkdir()
            suite.current_case = "suite"
            suite.commands = []
            suite.infrastructure_failure = None
            completed = subprocess.CompletedProcess(["ssh"], 255, "", "Connection refused")

            with mock.patch.object(REGRESSION.HYPERV.subprocess, "run", return_value=completed):
                with self.assertRaises(REGRESSION.InfrastructureFailure):
                    suite.command(["ssh"], vm="wgtcp-a", label="probe", timeout=20)

            self.assertEqual(len(suite.commands), 1)


if __name__ == "__main__":
    unittest.main()
