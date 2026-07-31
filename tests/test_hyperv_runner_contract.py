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
    def test_failure_reason_selects_assertion_before_guest_diagnostics(self):
        completed = subprocess.CompletedProcess(
            ["multipass"],
            1,
            "",
            "\n".join(
                [
                    "Failed to find cgroup2 mount",
                    "TCP tunnel did not reach 10.213.0.1 within 60 seconds",
                    'tcp-roaming-netns.sh failed at line 1645: return 1 (status 1)',
                    "--- wgtcp-rs-41197 TCP sockets ---",
                    "ESTAB 0 0 192.0.2.2:52220 192.0.2.129:41002",
                    "qdisc netem 10: parent 1:1 limit 1000 delay 60s",
                    " Sent 120 bytes 2 pkt (dropped 0, overlimits 0 requeues 0)",
                    " backlog 120b 2p requeues 0",
                    "E0000 00:00:1784016979.861273 9868 init.cc:229] "
                    "grpc_wait_for_shutdown_with_timeout() timed out.",
                ]
            ),
        )

        self.assertEqual(
            REGRESSION.failure_reason(completed),
            "TCP tunnel did not reach 10.213.0.1 within 60 seconds",
        )

    def test_failure_reason_uses_report_error_trace_only_as_fallback(self):
        completed = subprocess.CompletedProcess(
            ["multipass"],
            2,
            "",
            "\n".join(
                [
                    "Failed to find cgroup2 mount",
                    'tcp-roaming-netns.sh failed at line 112: return 2 (status 2)',
                    "--- wgtcp-rc-38033 addresses and routes ---",
                    "qdisc noqueue 0: dev lo root refcnt 2",
                    " backlog 0b 0p requeues 0",
                ]
            ),
        )

        self.assertEqual(
            REGRESSION.failure_reason(completed),
            "tcp-roaming-netns.sh failed at line 112: return 2 (status 2)",
        )

    def test_failure_reason_checks_stdout_after_multipass_boilerplate(self):
        completed = subprocess.CompletedProcess(
            ["multipass"],
            1,
            "guest assertion from stdout\n",
            "E0000 00:00:1 init.cc:229] "
            "grpc_wait_for_shutdown_with_timeout() timed out.\n",
        )

        self.assertEqual(
            REGRESSION.failure_reason(completed), "guest assertion from stdout"
        )

    def test_failure_reason_preserves_unrecognized_errors(self):
        completed = subprocess.CompletedProcess(
            ["multipass"], 2, "", "Error: Device for nexthop is not up.\n"
        )

        self.assertEqual(
            REGRESSION.failure_reason(completed),
            "Error: Device for nexthop is not up.",
        )

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
            "tcp-policy-reconnect-churn",
            "tcp-ipv6-dual-stack",
            "tcp-authenticated-carrier-lifetime",
            "tcp-nat44-dual-reachable",
            "tcp-nat44-dual-router-address-roam",
            "tcp-nat44-half-open-recovery",
            "tcp-debug-hostile-stream",
        ]
        suite = Harness({})
        suite.args.only_case = names

        self.assertEqual(run_quietly(suite), 0)
        self.assertEqual(suite.cases_run, names)

    def test_policy_churn_runs_on_both_guests_with_extended_timeout(self):
        suite = REGRESSION.Suite.__new__(REGRESSION.Suite)
        suite.args = SimpleNamespace(
            vm_a="wgtcp-a",
            vm_b="wgtcp-b",
            timeout=180,
            repo="/home/ubuntu/WireguardTCP",
            tcp_kernel_variant="fork",
        )
        suite.run_id = "contract"
        suite.managed_pair = lambda _case_id: nullcontext()
        modules = []
        helpers = []
        suite.module = lambda vm, variant: modules.append((vm, variant))

        def helper(vm, name, *args, **kwargs):
            helpers.append((vm, name, args, kwargs))
            return "mode=policy-churn\nconnect_proofs=20\n"

        suite.helper = helper

        details = suite.tcp_parity_netns_case("policy-churn")

        self.assertEqual(
            modules,
            [("wgtcp-a", "fork"), ("wgtcp-b", "fork")],
        )
        self.assertEqual([call[0] for call in helpers], ["wgtcp-a", "wgtcp-b"])
        for vm, name, args, kwargs in helpers:
            self.assertIn(vm, details["guests"])
            self.assertEqual(name, "guest-node.sh")
            self.assertEqual(
                args,
                (
                    "tcp-parity-netns",
                    "contract",
                    "tcp-parity-policy-churn",
                    "policy-churn",
                    "/home/ubuntu/WireguardTCP",
                ),
            )
            self.assertEqual(kwargs["label"], "tcp-parity-policy-churn")
            self.assertEqual(kwargs["timeout"], 900)

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

    def test_ssh_failure_reason_ignores_trailing_multipass_grpc_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = self.command_suite(Path(directory))
            completed = subprocess.CompletedProcess(
                ["multipass"],
                2,
                "",
                "exec failed: ssh connection failed: 'Timeout connecting to wgtcp-a'\n"
                "E0000 00:00:1 init.cc:229] "
                "grpc_wait_for_shutdown_with_timeout() timed out.\n",
            )
            with mock.patch.object(REGRESSION.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(
                    REGRESSION.InfrastructureFailure,
                    "ssh connection failed: 'Timeout connecting to wgtcp-a'",
                ):
                    suite.command(
                        ["multipass", "exec", "wgtcp-a", "--", "true"],
                        vm="wgtcp-a",
                        label="probe",
                        timeout=20,
                    )

            log = (suite.log_dir / "0001-suite-wgtcp-a-probe.log").read_text(
                encoding="utf-8"
            )
            self.assertIn("grpc_wait_for_shutdown_with_timeout", log)

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
