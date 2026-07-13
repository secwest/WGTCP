from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REGRESSION_PATH = Path(__file__).parent / "hyperv" / "regression.py"
SPEC = importlib.util.spec_from_file_location("hyperv_regression", REGRESSION_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {REGRESSION_PATH}")
REGRESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGRESSION)


def run_quietly(suite):
    with redirect_stdout(io.StringIO()):
        return suite.run()


class Harness(REGRESSION.Suite):
    def __init__(self, return_codes):
        self.args = SimpleNamespace(
            vm_a="wgtcp-a",
            vm_b="wgtcp-b",
            timeout=180,
            only_case=["preflight"],
            keep_going=True,
        )
        self.multipass = "multipass"
        self.current_case = "suite"
        self.commands = []
        self.results = []
        self.infrastructure_failure = None
        self.abort_reason = None
        self.case_number = 0
        self.return_codes = return_codes
        self.probes = []
        self.cases_run = []
        self.report_writes = 0

    def command(self, argv, *, vm, label, timeout=None):
        self.probes.append((argv, vm, label, timeout, self.current_case))
        return_code = self.return_codes.get(vm, 0)
        completed = subprocess.CompletedProcess(
            argv,
            return_code,
            "",
            "ssh connection failed" if return_code else "",
        )
        self.commands.append(
            {
                "duration_seconds": 0.1,
                "vm": vm,
                "return_code": return_code,
            }
        )
        return completed

    def run_case(self, name, function):
        self.cases_run.append(name)
        return True

    def write_report(self):
        self.report_writes += 1


class MidRunFailureHarness(Harness):
    run_case = REGRESSION.Suite.run_case

    def host_transport_preflight(self):
        return True

    def helper(self, vm, helper, *args, label=None, timeout=None):
        raise self.mark_infrastructure_failure(
            f"{vm} {label or helper}: ssh connection failed: simulated outage"
        )


class HyperVRunnerContractTests(unittest.TestCase):
    def test_host_transport_probe_precedes_case_execution(self):
        suite = Harness({})

        self.assertEqual(run_quietly(suite), 0)
        self.assertEqual(suite.cases_run, ["preflight"])
        self.assertEqual(len(suite.probes), 2)
        self.assertEqual(
            [probe[0] for probe in suite.probes],
            [
                ["multipass", "exec", "wgtcp-a", "--", "true"],
                ["multipass", "exec", "wgtcp-b", "--", "true"],
            ],
        )
        self.assertTrue(all(probe[2:] == ("host-transport-probe", 30, "infrastructure-preflight") for probe in suite.probes))
        self.assertEqual(suite.report_writes, 1)

    def test_transport_failure_aborts_even_with_keep_going(self):
        suite = Harness({"wgtcp-a": 1})

        self.assertEqual(run_quietly(suite), 2)
        self.assertEqual(suite.cases_run, [])
        self.assertEqual(len(suite.probes), 2)
        self.assertEqual(suite.report_writes, 1)
        self.assertEqual(len(suite.results), 1)
        result = suite.results[0]
        self.assertEqual(result["name"], "infrastructure-preflight")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["details"]["case_execution_started"])
        self.assertIn("wgtcp-a Multipass SSH probe", result["reason"])
        self.assertIn("no regression cases were run", result["reason"])

    def test_mid_run_transport_loss_aborts_even_with_keep_going(self):
        suite = MidRunFailureHarness({})

        self.assertEqual(run_quietly(suite), 2)
        self.assertEqual(suite.case_number, 1)
        self.assertEqual(suite.report_writes, 1)
        self.assertEqual(len(suite.results), 1)
        self.assertEqual(suite.results[0]["name"], "preflight")
        self.assertIn("ssh connection failed", suite.abort_reason)

    def test_tcp_parity_cases_are_independently_selectable(self):
        names = [
            "tcp-asymmetric-listen-ports",
            "tcp-full-tunnel-live-fwmark",
            "tcp-route-change",
            "tcp-source-address-uplink-change",
            "tcp-ipv6-dual-stack",
            "tcp-authenticated-carrier-lifetime",
            "tcp-debug-hostile-stream",
        ]
        suite = Harness({})
        suite.args.only_case = names

        self.assertEqual(run_quietly(suite), 0)
        self.assertEqual(suite.cases_run, names)

    def test_fault_case_requires_guest_side_production_restore(self):
        suite = REGRESSION.Suite.__new__(REGRESSION.Suite)
        suite.args = SimpleNamespace(
            vm_a="wgtcp-a",
            vm_b="wgtcp-b",
            timeout=180,
            repo="/home/ubuntu/WireguardTCP",
        )
        suite.run_id = "contract"
        suite.infrastructure_failure = None
        suite.managed_pair = lambda _case_id: nullcontext()
        suite.helper = lambda *_args, **_kwargs: (
            "status=pass\nrestored_kernel_variant=fork\n"
        )

        details = suite.tcp_fault_injection_case()

        self.assertEqual(details["kernel_variant"], "fork-fault")
        self.assertEqual(details["restored_kernel_variant"], "fork")

    def test_fault_case_rejects_missing_guest_side_restore(self):
        suite = REGRESSION.Suite.__new__(REGRESSION.Suite)
        suite.args = SimpleNamespace(
            vm_a="wgtcp-a",
            vm_b="wgtcp-b",
            timeout=180,
            repo="/home/ubuntu/WireguardTCP",
        )
        suite.run_id = "contract"
        suite.infrastructure_failure = None
        suite.managed_pair = lambda _case_id: nullcontext()
        suite.helper = lambda *_args, **_kwargs: "status=pass\n"

        with self.assertRaisesRegex(
            REGRESSION.Failure, "did not confirm production-module restoration"
        ):
            suite.tcp_fault_injection_case()

    def test_ssh_failure_is_classified_after_command_log_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = self.command_suite(Path(directory))
            completed = subprocess.CompletedProcess(
                ["multipass"],
                2,
                "",
                "exec failed: ssh connection failed: 'Timeout connecting to wgtcp-a'",
            )
            with mock.patch.object(REGRESSION.subprocess, "run", return_value=completed):
                with self.assertRaises(REGRESSION.InfrastructureFailure):
                    suite.command(
                        ["multipass", "exec", "wgtcp-a", "--", "true"],
                        vm="wgtcp-a",
                        label="probe",
                        timeout=20,
                    )

            self.assertEqual(len(suite.commands), 1)
            self.assertFalse(suite.commands[0]["host_timed_out"])
            self.assertTrue((suite.log_dir / "0001-suite-wgtcp-a-probe.log").is_file())

    def test_host_timeout_is_infrastructure_but_guest_124_is_not(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = self.command_suite(Path(directory))
            timeout = subprocess.TimeoutExpired(["multipass"], 20, output="partial")
            with mock.patch.object(REGRESSION.subprocess, "run", side_effect=timeout):
                with self.assertRaises(REGRESSION.InfrastructureFailure):
                    suite.command(
                        ["multipass"], vm="wgtcp-a", label="host-timeout", timeout=20
                    )
            self.assertTrue(suite.commands[0]["host_timed_out"])

        with tempfile.TemporaryDirectory() as directory:
            suite = self.command_suite(Path(directory))
            completed = subprocess.CompletedProcess(
                ["multipass"], 124, "", "guest helper timed out"
            )
            with mock.patch.object(REGRESSION.subprocess, "run", return_value=completed):
                returned = suite.command(
                    ["multipass"], vm="wgtcp-a", label="guest-timeout", timeout=20
                )
            self.assertEqual(returned.returncode, 124)
            self.assertIsNone(suite.infrastructure_failure)

    @staticmethod
    def command_suite(directory):
        suite = REGRESSION.Suite.__new__(REGRESSION.Suite)
        suite.args = SimpleNamespace(timeout=180)
        suite.results_dir = directory
        suite.log_dir = directory / "logs"
        suite.log_dir.mkdir()
        suite.current_case = "suite"
        suite.commands = []
        suite.infrastructure_failure = None
        return suite


if __name__ == "__main__":
    unittest.main()
