#!/usr/bin/env python3
"""Drive the two-VM WireguardTCP Linux regression suite through libvirt SSH."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys


HYPERV_RUNNER = Path(__file__).resolve().parents[1] / "hyperv" / "regression.py"
SPEC = importlib.util.spec_from_file_location("hyperv_regression", HYPERV_RUNNER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load shared regression suite: {HYPERV_RUNNER}")
HYPERV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HYPERV)

Failure = HYPERV.Failure
InfrastructureFailure = HYPERV.InfrastructureFailure


def find_ssh(explicit: str | None) -> str:
    candidates = [explicit, shutil.which(explicit) if explicit else None, shutil.which("ssh")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    raise Failure("OpenSSH client not found; pass --ssh")


class Suite(HYPERV.Suite):
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.ssh = find_ssh(args.ssh)
        self.started = HYPERV.dt.datetime.now(HYPERV.dt.timezone.utc)
        self.run_id = self.started.strftime("wg%Y%m%dT%H%M%SZ")
        results_base = args.results_dir or (Path(__file__).resolve().parent / "results")
        self.results_dir = (results_base / self.run_id).resolve()
        self.log_dir = self.results_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.commands: list[dict[str, object]] = []
        self.results: list[dict[str, object]] = []
        self.case_number = 0
        self.current_case = "suite"
        self.infrastructure_failure: InfrastructureFailure | None = None
        self.abort_reason: str | None = None

    def target(self, vm: str) -> str:
        hosts = {self.args.vm_a: self.args.vm_a_host, self.args.vm_b: self.args.vm_b_host}
        try:
            host = hosts[vm]
        except KeyError as error:
            raise Failure(f"unknown managed VM: {vm}") from error
        return f"{self.args.ssh_user}@{host}"

    def ssh_argv(self, vm: str, *remote_command: str) -> list[str]:
        known_hosts = self.args.known_hosts_dir / vm
        return [
            self.ssh,
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={min(self.args.timeout, 30)}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            self.target(vm),
            *remote_command,
        ]

    def command(
        self,
        argv: list[str],
        *,
        vm: str,
        label: str,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        completed = super().command(argv, vm=vm, label=label, timeout=timeout)
        if completed.returncode == 255:
            reason = completed.stderr.strip() or completed.stdout.strip() or "SSH transport failed"
            raise self.mark_infrastructure_failure(f"{vm} {label}: {reason.splitlines()[-1]}")
        return completed

    def remote(
        self,
        vm: str,
        helper: str,
        *arguments: object,
        label: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        host_timeout = self.args.timeout if timeout is None else timeout
        if host_timeout <= 10:
            raise Failure("command timeouts must be greater than ten seconds")
        guest_timeout = host_timeout - min(30, host_timeout - 1)
        script = f"{self.args.repo}/tests/hyperv/{helper}"
        remote_command = [
            "sudo",
            "--",
            "/usr/bin/timeout",
            "--verbose",
            "--signal=TERM",
            "--kill-after=5s",
            f"{guest_timeout}s",
            "bash",
            script,
            *[str(argument) for argument in arguments],
        ]
        return self.command(
            self.ssh_argv(vm, *remote_command),
            vm=vm,
            label=label or helper,
            timeout=host_timeout,
        )

    def preflight(self) -> dict[str, object]:
        details = super().preflight()
        details.pop("multipass", None)
        details["ssh"] = self.ssh
        details["transport"] = "libvirt-ssh"
        return details

    def host_transport_preflight(self) -> bool:
        self.current_case = "infrastructure-preflight"
        print("[CHECK] libvirt SSH host transport", flush=True)
        errors: list[str] = []
        probe_timeout = min(self.args.timeout, 30)
        for vm in (self.args.vm_a, self.args.vm_b):
            try:
                completed = self.command(
                    self.ssh_argv(vm, "true"),
                    vm=vm,
                    label="host-transport-probe",
                    timeout=probe_timeout,
                )
                self.require(completed, f"{vm} SSH probe")
            except Exception as error:
                errors.append(str(error))

        if not errors:
            print("[ OK ] libvirt SSH host transport", flush=True)
            return True

        reason = (
            "host transport preflight failed; no regression cases were run: "
            + "; ".join(errors)
        )
        self.abort_reason = reason
        self.results.append(
            {
                "name": "infrastructure-preflight",
                "status": "FAIL",
                "reason": reason,
                "duration_seconds": round(
                    sum(float(command["duration_seconds"]) for command in self.commands), 3
                ),
                "details": {"case_execution_started": False},
            }
        )
        print(f"[FAIL] infrastructure-preflight: {reason}", flush=True)
        return False

    def write_report(self) -> None:
        super().write_report()
        report = self.results_dir / "report.md"
        report.write_text(
            report.read_text(encoding="utf-8").replace(
                "# WireguardTCP Hyper-V Regression",
                "# WireguardTCP Linux libvirt Regression",
                1,
            ),
            encoding="utf-8",
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--vm-a", default="wgtcp-a")
    result.add_argument("--vm-b", default="wgtcp-b")
    result.add_argument("--vm-a-host", required=True)
    result.add_argument("--vm-b-host", required=True)
    result.add_argument("--ssh", help="path to the OpenSSH client")
    result.add_argument("--ssh-user", default="ubuntu")
    result.add_argument(
        "--known-hosts-dir",
        type=Path,
        required=True,
        help="directory containing one verified known-hosts file per VM",
    )
    result.add_argument("--repo", default="/home/ubuntu/WireguardTCP")
    result.add_argument("--results-dir", type=Path)
    result.add_argument("--timeout", type=int, default=180)
    result.add_argument("--prepare-timeout", type=int, default=1800)
    result.add_argument("--keep-going", action="store_true")
    result.add_argument("--prepare", action="store_true", help="bootstrap and build both guests first")
    result.add_argument(
        "--only-case",
        action="append",
        metavar="NAME",
        help="run only this named case; repeat to select multiple cases",
    )
    result.add_argument(
        "--tcp-kernel-variant",
        choices=("fork", "fork-debug"),
        default="fork",
        help="fork module build used by TCP cases (default: fork)",
    )
    result.add_argument("--path0-a", default="10.77.0.10")
    result.add_argument("--path0-b", default="10.77.0.11")
    result.add_argument("--path1-a", default="10.77.1.10")
    result.add_argument("--path1-b", default="10.77.1.11")
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        if not args.known_hosts_dir.is_dir():
            raise Failure(f"known-hosts directory does not exist: {args.known_hosts_dir}")
        return Suite(args).run()
    except (Failure, OSError) as error:
        print(f"regression: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
