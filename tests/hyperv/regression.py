#!/usr/bin/env python3
"""Drive the two-VM WireguardTCP Hyper-V regression suite through Multipass."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Callable, Iterator


class Failure(RuntimeError):
    pass


class InfrastructureFailure(Failure):
    pass


class Skip(RuntimeError):
    pass


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "command"


def parse_fields(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


_REPORT_ERROR_TRACE = re.compile(
    r"^\S+\.sh failed at line \d+: .+ \(status \d+\)$"
)
_MULTIPASS_GRPC_BOILERPLATE = re.compile(
    r"^[EWI]\d{4}\s+.*grpc_wait_for_shutdown_with_timeout\(\) timed out\.?$"
)
_DUMP_SECTION = re.compile(r"^--- .+ ---$")
_QDISC_STATE = re.compile(
    r"^(?:qdisc\s|Sent \d+ bytes \d+ pkt\b|backlog \d+b \d+p\b)",
    re.IGNORECASE,
)


def failure_reason(completed: subprocess.CompletedProcess[str]) -> str:
    """Choose a concise assertion while leaving complete output in the command log."""
    trace_fallback: str | None = None
    for output in (completed.stderr or "", completed.stdout or ""):
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if _DUMP_SECTION.fullmatch(line):
                # Guest helpers append structured state dumps after their assertion.
                break
            if line == "Failed to find cgroup2 mount":
                continue
            if _MULTIPASS_GRPC_BOILERPLATE.fullmatch(line):
                continue
            if _QDISC_STATE.match(line):
                continue
            if _REPORT_ERROR_TRACE.fullmatch(line):
                if trace_fallback is None:
                    trace_fallback = line
                continue
            return line
    return trace_fallback or f"exit {completed.returncode}"


def find_multipass(explicit: str | None) -> str:
    candidates = [
        explicit,
        shutil.which(explicit) if explicit else None,
        shutil.which("multipass.exe"),
        shutil.which("multipass"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Multipass", "bin", "multipass.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Multipass", "multipass.exe"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    raise Failure("multipass executable not found; pass --multipass")


class Suite:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.multipass = find_multipass(args.multipass)
        self.started = dt.datetime.now(dt.timezone.utc)
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

    def mark_infrastructure_failure(self, reason: str) -> InfrastructureFailure:
        error = InfrastructureFailure(reason)
        if self.infrastructure_failure is None:
            self.infrastructure_failure = error
        return error

    def command(
        self,
        argv: list[str],
        *,
        vm: str,
        label: str,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        number = len(self.commands) + 1
        filename = f"{number:04d}-{safe_name(self.current_case)}-{safe_name(vm)}-{safe_name(label)}.log"
        path = self.log_dir / filename
        began = time.monotonic()
        host_timed_out = False
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.args.timeout if timeout is None else timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            host_timed_out = True
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            completed = subprocess.CompletedProcess(argv, 124, stdout, stderr + "\nTIMEOUT\n")
        duration = time.monotonic() - began
        path.write_text(
            f"COMMAND: {json.dumps(argv)}\nRETURN CODE: {completed.returncode}\n"
            f"DURATION: {duration:.3f}s\n\nSTDOUT\n{completed.stdout}\nSTDERR\n{completed.stderr}",
            encoding="utf-8",
        )
        self.commands.append(
            {
                "case": self.current_case,
                "vm": vm,
                "label": label,
                "argv": argv,
                "return_code": completed.returncode,
                "duration_seconds": round(duration, 3),
                "host_timed_out": host_timed_out,
                "log": str(path.relative_to(self.results_dir)),
            }
        )
        if host_timed_out:
            raise self.mark_infrastructure_failure(
                f"{vm} {label}: host command timed out after {timeout or self.args.timeout}s"
            )
        combined_output = f"{completed.stdout}\n{completed.stderr}".lower()
        if completed.returncode != 0 and "ssh connection failed:" in combined_output:
            raise self.mark_infrastructure_failure(
                f"{vm} {label}: {failure_reason(completed)}"
            )
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
        argv = [
            self.multipass,
            "exec",
            vm,
            "--",
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
        return self.command(argv, vm=vm, label=label or helper, timeout=host_timeout)

    @staticmethod
    def require(completed: subprocess.CompletedProcess[str], context: str) -> str:
        if completed.returncode == 77:
            raise Skip(f"{context}: {completed.stderr.strip() or completed.stdout.strip()}")
        if completed.returncode != 0:
            raise Failure(f"{context}: {failure_reason(completed)}")
        return completed.stdout

    def helper(
        self,
        vm: str,
        helper: str,
        *args: object,
        label: str | None = None,
        timeout: int | None = None,
    ) -> str:
        return self.require(
            self.remote(vm, helper, *args, label=label, timeout=timeout),
            f"{vm} {label or helper}",
        )

    def module(self, vm: str, variant: str) -> None:
        self.helper(vm, "guest-module.sh", variant, label=f"module-{variant}")

    def cleanup(self, vm: str, case_id: str, iface: str = "wgt0") -> None:
        self.require(
            self.remote(
                vm,
                "guest-node.sh",
                "cleanup",
                self.run_id,
                case_id,
                iface,
                label="cleanup",
            ),
            f"{vm} cleanup",
        )

    @contextmanager
    def managed_pair(
        self,
        case_id: str,
        iface: str = "wgt0",
        failure_collect: tuple[str, str] | None = None,
    ) -> Iterator[None]:
        primary: BaseException | None = None
        try:
            yield
        except InfrastructureFailure:
            raise
        except BaseException as error:
            primary = error
            if failure_collect is not None:
                self.collect_pair_best_effort(*failure_collect, iface=iface)
            if self.infrastructure_failure is not None:
                raise self.infrastructure_failure

        cleanup_errors: list[str] = []
        for vm in (self.args.vm_a, self.args.vm_b):
            try:
                self.cleanup(vm, case_id, iface)
            except InfrastructureFailure:
                raise
            except Exception as error:
                cleanup_errors.append(f"{vm}: {error}")

        if cleanup_errors:
            cleanup_reason = "; ".join(cleanup_errors)
            if isinstance(primary, Exception):
                raise Failure(f"{primary}; cleanup also failed: {cleanup_reason}") from primary
            if primary is not None:
                raise primary
            raise Failure(f"cleanup failed: {cleanup_reason}")
        if primary is not None:
            raise primary

    def prepare_pair(
        self,
        case_id: str,
        tool_a: str,
        tool_b: str,
        transport: str,
        subnet: int,
        port_a: str = "omit",
        port_b: str = "omit",
    ) -> tuple[dict[str, str], dict[str, str], str, str]:
        address_a = f"10.250.{subnet}.1/30"
        address_b = f"10.250.{subnet}.2/30"
        out_a = self.helper(
            self.args.vm_a, "guest-node.sh", "prepare", self.run_id, case_id,
            "wgt0", tool_a, transport, address_a, port_a, label="prepare",
        )
        out_b = self.helper(
            self.args.vm_b, "guest-node.sh", "prepare", self.run_id, case_id,
            "wgt0", tool_b, transport, address_b, port_b, label="prepare",
        )
        node_a, node_b = parse_fields(out_a), parse_fields(out_b)
        for name, node in (("A", node_a), ("B", node_b)):
            if not node.get("public_key") or not node.get("listen_port", "").isdigit():
                raise Failure(f"node {name} returned incomplete preparation data")
        self.helper(
            self.args.vm_a, "guest-node.sh", "peer", self.run_id, case_id, "wgt0",
            tool_a, node_b["public_key"], f"10.250.{subnet}.2/32",
            f"{self.args.path0_b}:{node_b['listen_port']}", label="configure-peer",
        )
        self.helper(
            self.args.vm_b, "guest-node.sh", "peer", self.run_id, case_id, "wgt0",
            tool_b, node_a["public_key"], f"10.250.{subnet}.1/32",
            f"{self.args.path0_a}:{node_a['listen_port']}", label="configure-peer",
        )
        return node_a, node_b, address_a.split("/")[0], address_b.split("/")[0]

    def collect_pair(self, tool_a: str, tool_b: str, iface: str = "wgt0") -> None:
        self.helper(self.args.vm_a, "guest-node.sh", "collect", iface, tool_a, label="collect")
        self.helper(self.args.vm_b, "guest-node.sh", "collect", iface, tool_b, label="collect")

    def collect_pair_best_effort(
        self, tool_a: str, tool_b: str, iface: str = "wgt0"
    ) -> None:
        for vm, tool in ((self.args.vm_a, tool_a), (self.args.vm_b, tool_b)):
            try:
                self.remote(
                    vm,
                    "guest-node.sh",
                    "collect",
                    iface,
                    tool,
                    label="failure-collect",
                )
            except InfrastructureFailure:
                break
            except Exception:
                # Preserve the primary test failure even if diagnostic capture fails.
                pass

    def udp_matrix_case(
        self, kernel_a: str, kernel_b: str, tool_a: str, tool_b: str, subnet: int
    ) -> dict[str, object]:
        case_id = f"m{self.case_number}"
        with self.managed_pair(case_id, failure_collect=(tool_a, tool_b)):
            self.module(self.args.vm_a, kernel_a)
            self.module(self.args.vm_b, kernel_b)
            node_a, node_b, address_a, address_b = self.prepare_pair(
                case_id, tool_a, tool_b, "udp", subnet
            )
            self.helper(self.args.vm_a, "guest-node.sh", "listener", "wgt0", "udp")
            self.helper(self.args.vm_b, "guest-node.sh", "listener", "wgt0", "udp")
            self.helper(self.args.vm_a, "guest-node.sh", "ping", "wgt0", address_b)
            self.helper(self.args.vm_b, "guest-node.sh", "ping", "wgt0", address_a)
            self.collect_pair(tool_a, tool_b)
            return {"port_a": int(node_a["listen_port"]), "port_b": int(node_b["listen_port"])}

    def roaming_case(self) -> dict[str, object]:
        case_id = "roaming"
        with self.managed_pair(case_id, failure_collect=("stock", "fork")):
            self.module(self.args.vm_a, "fork")
            self.module(self.args.vm_b, "fork")
            node_a, node_b, address_a, address_b = self.prepare_pair(
                case_id, "stock", "fork", "udp", 220
            )
            self.helper(self.args.vm_a, "guest-node.sh", "ping", "wgt0", address_b)
            self.helper(
                self.args.vm_a, "guest-node.sh", "endpoint", self.run_id, case_id,
                "wgt0", "stock", node_b["public_key"],
                f"{self.args.path1_b}:{node_b['listen_port']}", label="roam-source",
            )
            self.helper(self.args.vm_a, "guest-node.sh", "ping", "wgt0", address_b)
            endpoint_output = self.helper(
                self.args.vm_b, "guest-node.sh", "get-endpoint", "wgt0", "fork",
                node_a["public_key"], label="learned-endpoint",
            )
            learned = parse_fields(endpoint_output).get("endpoint")
            expected = f"{self.args.path1_a}:{node_a['listen_port']}"
            if learned != expected:
                raise Failure(f"roaming endpoint is {learned!r}, expected {expected!r}")
            self.helper(self.args.vm_b, "guest-node.sh", "ping", "wgt0", address_a)
            self.collect_pair("stock", "fork")
            return {"learned_endpoint": learned}

    def output_random_case(self) -> dict[str, object]:
        case_id = "output"
        with self.managed_pair(case_id, failure_collect=("fork", "stock")):
            self.module(self.args.vm_a, "fork")
            self.module(self.args.vm_b, "fork")
            self.prepare_pair(case_id, "fork", "stock", "udp", 221)
            self.helper(self.args.vm_a, "guest-node.sh", "output-parity", "wgt0")
            random_output = self.helper(
                self.args.vm_b,
                "guest-node.sh",
                "random-ports",
                self.run_id,
                case_id,
                "fork",
            )
            return parse_fields(random_output)

    def tcp_case(self) -> dict[str, object]:
        case_id = "tcp"
        with self.managed_pair(case_id, failure_collect=("fork", "fork")):
            self.module(self.args.vm_a, self.args.tcp_kernel_variant)
            self.module(self.args.vm_b, self.args.tcp_kernel_variant)
            _, _, address_a, address_b = self.prepare_pair(
                case_id, "fork", "fork", "tcp", 222, "52010", "52010"
            )
            self.helper(self.args.vm_a, "guest-node.sh", "listener", "wgt0", "tcp")
            self.helper(self.args.vm_b, "guest-node.sh", "listener", "wgt0", "tcp")
            self.helper(self.args.vm_a, "guest-node.sh", "wait-ping", "wgt0", address_b, 60)
            self.helper(self.args.vm_b, "guest-node.sh", "wait-ping", "wgt0", address_a, 60)
            self.collect_pair("fork", "fork")
            return {
                "port_a": 52010,
                "port_b": 52010,
                "kernel_variant": self.args.tcp_kernel_variant,
            }

    def tcp_asymmetric_ports_case(self) -> dict[str, object]:
        case_id = "tcp-asymmetric"
        port_a, port_b = "52020", "52021"
        with self.managed_pair(case_id, failure_collect=("fork", "fork")):
            self.module(self.args.vm_a, self.args.tcp_kernel_variant)
            self.module(self.args.vm_b, self.args.tcp_kernel_variant)
            node_a, node_b, address_a, address_b = self.prepare_pair(
                case_id, "fork", "fork", "tcp", 225, port_a, port_b
            )
            if node_a["listen_port"] != port_a or node_b["listen_port"] != port_b:
                raise Failure("TCP listeners did not retain their asymmetric configured ports")
            self.helper(self.args.vm_a, "guest-node.sh", "listener", "wgt0", "tcp")
            self.helper(self.args.vm_b, "guest-node.sh", "listener", "wgt0", "tcp")
            self.helper(self.args.vm_a, "guest-node.sh", "wait-ping", "wgt0", address_b, 60)
            self.helper(self.args.vm_b, "guest-node.sh", "wait-ping", "wgt0", address_a, 60)
            path_a = parse_fields(
                self.helper(
                    self.args.vm_a,
                    "guest-node.sh",
                    "tcp-asymmetric-path",
                    self.args.path0_a,
                    self.args.path0_b,
                    port_a,
                    port_b,
                    label="verify-asymmetric-tcp",
                )
            )
            path_b = parse_fields(
                self.helper(
                    self.args.vm_b,
                    "guest-node.sh",
                    "tcp-asymmetric-path",
                    self.args.path0_b,
                    self.args.path0_a,
                    port_b,
                    port_a,
                    label="verify-reverse-asymmetric-tcp",
                )
            )
            self.collect_pair("fork", "fork")
            return {
                "port_a": int(port_a),
                "port_b": int(port_b),
                "path_a": path_a.get("tcp_path", ""),
                "path_b": path_b.get("tcp_path", ""),
                "forward": "pass",
                "reverse": "pass",
                "kernel_variant": self.args.tcp_kernel_variant,
            }

    def tcp_stock_management_case(self) -> dict[str, object]:
        case_id = "tcp-stock-management"
        with self.managed_pair(case_id, failure_collect=("fork", "fork")):
            self.module(self.args.vm_a, self.args.tcp_kernel_variant)
            self.module(self.args.vm_b, self.args.tcp_kernel_variant)
            node_a, node_b, address_a, address_b = self.prepare_pair(
                case_id, "fork", "fork", "tcp", 223, "52011", "52011"
            )
            for vm, peer_key in (
                (self.args.vm_a, node_b["public_key"]),
                (self.args.vm_b, node_a["public_key"]),
            ):
                self.helper(
                    vm,
                    "guest-node.sh",
                    "stock-tcp-management",
                    self.run_id,
                    case_id,
                    "wgt0",
                    peer_key,
                    label="stock-tcp-management",
                )
            self.helper(self.args.vm_a, "guest-node.sh", "wait-ping", "wgt0", address_b, 60)
            self.helper(self.args.vm_b, "guest-node.sh", "wait-ping", "wgt0", address_a, 60)
            self.collect_pair("stock", "stock")
            return {
                "stock_tool_management": "pass",
                "transport": "tcp",
                "kernel_variant": self.args.tcp_kernel_variant,
            }

    def tcp_configured_path_change_case(self) -> dict[str, object]:
        case_id = "tcp-path-change"
        with self.managed_pair(case_id, failure_collect=("fork", "fork")):
            self.module(self.args.vm_a, self.args.tcp_kernel_variant)
            self.module(self.args.vm_b, self.args.tcp_kernel_variant)
            node_a, node_b, address_a, address_b = self.prepare_pair(
                case_id, "fork", "fork", "tcp", 224, "52012", "52012"
            )
            self.helper(self.args.vm_a, "guest-node.sh", "wait-ping", "wgt0", address_b, 60)
            self.helper(self.args.vm_b, "guest-node.sh", "wait-ping", "wgt0", address_a, 60)

            expected_a = f"{self.args.path1_b}:{node_b['listen_port']}"
            expected_b = f"{self.args.path1_a}:{node_a['listen_port']}"
            self.helper(
                self.args.vm_a,
                "guest-node.sh",
                "endpoint",
                self.run_id,
                case_id,
                "wgt0",
                "fork",
                node_b["public_key"],
                expected_a,
                label="configure-path1-peer",
            )
            self.helper(
                self.args.vm_b,
                "guest-node.sh",
                "endpoint",
                self.run_id,
                case_id,
                "wgt0",
                "fork",
                node_a["public_key"],
                expected_b,
                label="configure-path1-peer",
            )
            for vm, peer_key, expected in (
                (self.args.vm_a, node_b["public_key"], expected_a),
                (self.args.vm_b, node_a["public_key"], expected_b),
            ):
                observed = parse_fields(
                    self.helper(
                        vm,
                        "guest-node.sh",
                        "get-endpoint",
                        "wgt0",
                        "fork",
                        peer_key,
                        label="configured-path1-endpoint",
                    )
                ).get("endpoint")
                if observed != expected:
                    raise Failure(f"{vm} endpoint is {observed!r}, expected {expected!r}")

            self.helper(
                self.args.vm_a,
                "guest-node.sh",
                "underlay-state",
                self.run_id,
                case_id,
                self.args.path0_a,
                "down",
                label="disable-path0",
            )
            self.helper(
                self.args.vm_b,
                "guest-node.sh",
                "underlay-state",
                self.run_id,
                case_id,
                self.args.path0_b,
                "down",
                label="disable-path0",
            )
            for state in ("down", "up"):
                for vm in (self.args.vm_a, self.args.vm_b):
                    self.helper(
                        vm,
                        "guest-node.sh",
                        "link-state",
                        self.run_id,
                        case_id,
                        "wgt0",
                        state,
                        label=f"wireguard-{state}",
                    )

            self.helper(
                self.args.vm_a, "guest-node.sh", "wait-ping", "wgt0", address_b, 60
            )
            self.helper(
                self.args.vm_b, "guest-node.sh", "wait-ping", "wgt0", address_a, 60
            )
            self.helper(
                self.args.vm_a,
                "guest-node.sh",
                "tcp-path",
                self.args.path1_a,
                self.args.path1_b,
                node_b["listen_port"],
                label="verify-path1-tcp",
            )
            self.helper(
                self.args.vm_b,
                "guest-node.sh",
                "tcp-path",
                self.args.path1_b,
                self.args.path1_a,
                node_a["listen_port"],
                label="verify-reverse-path1-tcp",
            )
            self.collect_pair("fork", "fork")
            return {
                "endpoint_a": expected_a,
                "endpoint_b": expected_b,
                "forward": "pass",
                "reverse": "pass",
                "outer_path": "path1",
                "kernel_variant": self.args.tcp_kernel_variant,
            }

    def preflight_details(self) -> dict[str, object]:
        return {"multipass": self.multipass, "repo": self.args.repo}

    def preflight(self) -> dict[str, object]:
        for vm, path0, path1 in (
            (self.args.vm_a, self.args.path0_a, self.args.path1_a),
            (self.args.vm_b, self.args.path0_b, self.args.path1_b),
        ):
            if self.args.prepare:
                self.helper(
                    vm,
                    "guest-bootstrap.sh",
                    self.args.repo,
                    timeout=self.args.prepare_timeout,
                )
                self.helper(
                    vm,
                    "guest-build.sh",
                    self.args.repo,
                    timeout=self.args.prepare_timeout,
                )
            self.helper(vm, "guest-build.sh", "--verify")
            self.helper(vm, "guest-node.sh", "diagnose")
            self.helper(vm, "guest-node.sh", "underlay", path0, path1)
            self.helper(vm, "guest-node.sh", "contract-tests", self.args.repo)
        return self.preflight_details()

    def udp_netns_case(self) -> dict[str, object]:
        case_id = "udp-netns"
        with self.managed_pair(case_id):
            for vm in (self.args.vm_a, self.args.vm_b):
                self.module(vm, "fork")
                self.helper(
                    vm,
                    "guest-node.sh",
                    "udp-netns",
                    self.run_id,
                    case_id,
                    self.args.repo,
                )
            return {"vms_tested": [self.args.vm_a, self.args.vm_b]}

    def tcp_parity_netns_case(self, mode: str) -> dict[str, object]:
        case_id = f"tcp-parity-{mode}"
        details: dict[str, object] = {"mode": mode, "guests": {}}
        with self.managed_pair(case_id):
            guest_details: dict[str, dict[str, str]] = {}
            for vm in (self.args.vm_a, self.args.vm_b):
                self.module(vm, self.args.tcp_kernel_variant)
                output = self.helper(
                    vm,
                    "guest-node.sh",
                    "tcp-parity-netns",
                    self.run_id,
                    case_id,
                    mode,
                    self.args.repo,
                    label=f"tcp-parity-{mode}",
                    timeout=max(
                        self.args.timeout,
                        900 if mode == "policy-churn" else 240,
                    ),
                )
                guest_details[vm] = parse_fields(output)
            details["guests"] = guest_details
            details["kernel_variant"] = self.args.tcp_kernel_variant
            return details

    def tcp_roaming_netns_case(self, mode: str) -> dict[str, object]:
        case_id = f"tcp-roaming-{mode}"
        details: dict[str, object] = {"mode": mode, "guests": {}}
        with self.managed_pair(case_id):
            guest_details: dict[str, dict[str, str]] = {}
            for vm in (self.args.vm_a, self.args.vm_b):
                self.module(vm, self.args.tcp_kernel_variant)
                output = self.helper(
                    vm,
                    "guest-node.sh",
                    "tcp-roaming-netns",
                    self.run_id,
                    case_id,
                    mode,
                    self.args.repo,
                    label=f"tcp-roaming-{mode}",
                    timeout=max(self.args.timeout, 600),
                )
                guest_details[vm] = parse_fields(output)
            details["guests"] = guest_details
            details["kernel_variant"] = self.args.tcp_kernel_variant
            return details

    def tcp_nat_netns_case(self, mode: str) -> dict[str, object]:
        case_id = f"tcp-nat-{mode}"
        details: dict[str, object] = {"mode": mode, "guests": {}}
        with self.managed_pair(case_id):
            guest_details: dict[str, dict[str, str]] = {}
            for vm in (self.args.vm_a, self.args.vm_b):
                self.module(vm, self.args.tcp_kernel_variant)
                output = self.helper(
                    vm,
                    "guest-node.sh",
                    "tcp-nat-netns",
                    self.run_id,
                    case_id,
                    mode,
                    self.args.repo,
                    label=f"tcp-nat-{mode}",
                    timeout=max(self.args.timeout, 300),
                )
                guest_details[vm] = parse_fields(output)
            details["guests"] = guest_details
            details["kernel_variant"] = self.args.tcp_kernel_variant
            return details

    def debug_selftest_case(self) -> dict[str, object]:
        self.module(self.args.vm_a, "fork-debug")
        status = parse_fields(
            self.helper(self.args.vm_a, "guest-module.sh", "status", label="debug-status")
        )
        if (
            status.get("variant") != "fork-debug"
            or status.get("loaded") != "true"
            or status.get("unloadable") != "true"
        ):
            raise Failure("debug module did not remain loaded after its initialization self-tests")
        return {
            "variant": "fork-debug",
            "loaded": True,
            "unloadable": True,
            "initialization_selftests": "pass",
        }

    def tcp_fault_injection_case(self) -> dict[str, object]:
        case_id = "tcp-fault-injection"
        details: dict[str, object] = {"guests": {}}
        with self.managed_pair(case_id):
            guest_details: dict[str, dict[str, str]] = {}
            for vm in (self.args.vm_a, self.args.vm_b):
                output = self.helper(
                    vm,
                    "guest-node.sh",
                    "tcp-parity-netns",
                    self.run_id,
                    case_id,
                    "fault-injection",
                    self.args.repo,
                    label="tcp-fault-injection",
                    timeout=max(self.args.timeout, 240),
                )
                fields = parse_fields(output)
                if fields.get("restored_kernel_variant") != "fork":
                    raise Failure(
                        f"{vm} did not confirm production-module restoration"
                    )
                guest_details[vm] = fields
            details["guests"] = guest_details
            details["kernel_variant"] = "fork-fault"
            details["restored_kernel_variant"] = "fork"
            return details

    def stock_capability_case(self) -> dict[str, object]:
        case_id = "stock-capability"
        iface = "wgstockcap"
        with self.managed_pair(case_id, iface):
            self.module(self.args.vm_a, "stock")
            self.helper(
                self.args.vm_a,
                "guest-node.sh",
                "stock-capability",
                self.run_id,
                case_id,
                iface,
            )
            return {"guard": "pass"}

    def mode_rejection_case(self) -> dict[str, object]:
        case_id = "mode-rejection"
        iface = "wgmodecheck"
        with self.managed_pair(case_id, iface):
            self.module(self.args.vm_a, "fork")
            self.helper(
                self.args.vm_a,
                "guest-node.sh",
                "mode-rejection",
                self.run_id,
                case_id,
                iface,
            )
            return {"guard": "pass"}

    def host_transport_preflight(self) -> bool:
        self.current_case = "infrastructure-preflight"
        print("[CHECK] Multipass host transport", flush=True)
        errors: list[str] = []
        probe_timeout = min(self.args.timeout, 30)
        for vm in (self.args.vm_a, self.args.vm_b):
            try:
                completed = self.command(
                    [self.multipass, "exec", vm, "--", "true"],
                    vm=vm,
                    label="host-transport-probe",
                    timeout=probe_timeout,
                )
                self.require(completed, f"{vm} Multipass SSH probe")
            except Exception as error:
                errors.append(str(error))

        if not errors:
            print("[ OK ] Multipass host transport", flush=True)
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

    def run_case(self, name: str, function: Callable[[], dict[str, object]]) -> bool:
        self.case_number += 1
        self.current_case = name
        began = time.monotonic()
        print(f"[RUN ] {name}", flush=True)
        details: dict[str, object] = {}
        case_error: Exception | None = None
        reset_vms: list[str] = []
        try:
            for vm in (self.args.vm_a, self.args.vm_b):
                self.helper(vm, "guest-node.sh", "kernel-log-reset", label="kernel-log-reset")
                reset_vms.append(vm)
            details = function()
        except Exception as error:  # Keep report generation alive after a failed case.
            case_error = error

        kernel_log_errors: list[str] = []
        if self.infrastructure_failure is None:
            for vm in reset_vms:
                try:
                    self.helper(vm, "guest-node.sh", "kernel-log-check", label="kernel-log-check")
                except Exception as error:
                    kernel_log_errors.append(f"{vm}: {error}")

        if kernel_log_errors:
            log_reason = "; ".join(kernel_log_errors)
            reason = f"{case_error}; kernel log check also failed: {log_reason}" if case_error else log_reason
            details, status = {}, "FAIL"
        elif isinstance(case_error, Skip):
            details, status, reason = {}, "SKIP", str(case_error)
        elif case_error is not None:
            details, status, reason = {}, "FAIL", str(case_error)
        else:
            status, reason = "PASS", ""
        duration = time.monotonic() - began
        self.results.append(
            {
                "name": name,
                "status": status,
                "reason": reason,
                "duration_seconds": round(duration, 3),
                "details": details,
            }
        )
        suffix = f": {reason}" if reason else ""
        print(f"[{status:4}] {name}{suffix}", flush=True)
        if self.infrastructure_failure is not None:
            raise self.infrastructure_failure
        return status == "PASS"

    def write_report(self) -> None:
        finished = dt.datetime.now(dt.timezone.utc)
        counts = {status: sum(r["status"] == status for r in self.results) for status in ("PASS", "FAIL", "SKIP")}
        document = {
            "schema_version": 1,
            "run_id": self.run_id,
            "started_at": self.started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round((finished - self.started).total_seconds(), 3),
            "aborted": self.abort_reason is not None,
            "abort_reason": self.abort_reason or "",
            "vms": {"a": self.args.vm_a, "b": self.args.vm_b},
            "underlay": {
                "path0": {"a": self.args.path0_a, "b": self.args.path0_b},
                "path1": {"a": self.args.path1_a, "b": self.args.path1_b},
            },
            "summary": counts,
            "results": self.results,
            "commands": self.commands,
        }
        (self.results_dir / "report.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        lines = [
            "# WireguardTCP Hyper-V Regression",
            "",
            f"Run: `{self.run_id}`  ",
            f"VMs: `{self.args.vm_a}`, `{self.args.vm_b}`  ",
            f"Summary: **{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['SKIP']} SKIP**",
        ]
        if self.abort_reason:
            lines.extend([f"Aborted: **yes** ({self.abort_reason})", ""])
        else:
            lines.append("")
        lines.extend([
            "| Status | Case | Duration | Reason |",
            "|---|---|---:|---|",
        ])
        for result in self.results:
            reason = str(result["reason"]).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {result['status']} | `{result['name']}` | {result['duration_seconds']}s | {reason} |"
            )
        lines.extend(["", "Per-command stdout and stderr are retained in `logs/`.", ""])
        (self.results_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")

    def run(self) -> int:
        cases: list[tuple[str, Callable[[], dict[str, object]]]] = [("preflight", self.preflight)]
        subnet = 1
        for kernel_a, kernel_b, tool_a, tool_b in itertools.product(
            ("stock", "fork"), repeat=4
        ):
            name = f"udp-ka-{kernel_a}-kb-{kernel_b}-ta-{tool_a}-tb-{tool_b}"
            cases.append(
                (
                    name,
                    lambda ka=kernel_a, kb=kernel_b, ta=tool_a, tb=tool_b, sn=subnet:
                    self.udp_matrix_case(ka, kb, ta, tb, sn),
                )
            )
            subnet += 1
        cases.extend(
            [
                ("fork-udp-netns-regression", self.udp_netns_case),
                ("fork-debug-initialization-selftests", self.debug_selftest_case),
                ("udp-roaming-path-change", self.roaming_case),
                ("udp-output-and-random-port", self.output_random_case),
                (
                    "stock-kernel-transport-capability",
                    self.stock_capability_case,
                ),
                (
                    "fork-mode-change-rejection",
                    self.mode_rejection_case,
                ),
                ("tcp-smoke", self.tcp_case),
                ("tcp-asymmetric-listen-ports", self.tcp_asymmetric_ports_case),
                ("tcp-stock-tool-management", self.tcp_stock_management_case),
                (
                    "tcp-config-roundtrip",
                    lambda: self.tcp_parity_netns_case("config-roundtrip"),
                ),
                ("tcp-configured-path-change", self.tcp_configured_path_change_case),
                (
                    "tcp-full-tunnel-live-fwmark",
                    lambda: self.tcp_parity_netns_case("fwmark"),
                ),
                (
                    "tcp-route-change",
                    lambda: self.tcp_parity_netns_case("route"),
                ),
                (
                    "tcp-source-address-uplink-change",
                    lambda: self.tcp_parity_netns_case("source-uplink"),
                ),
                (
                    "tcp-policy-reconnect-churn",
                    lambda: self.tcp_parity_netns_case("policy-churn"),
                ),
                (
                    "tcp-ipv6-dual-stack",
                    lambda: self.tcp_parity_netns_case("ipv6"),
                ),
                (
                    "tcp-ipv6-link-local-scope",
                    lambda: self.tcp_parity_netns_case("ipv6-link-local"),
                ),
                (
                    "tcp-authenticated-carrier-lifetime",
                    lambda: self.tcp_parity_netns_case("carrier-lifetime"),
                ),
                (
                    "tcp-nat44-single-private",
                    lambda: self.tcp_nat_netns_case("single-private"),
                ),
                (
                    "tcp-nat44-dual-reachable",
                    lambda: self.tcp_nat_netns_case("dual-reachable"),
                ),
                (
                    "tcp-nat44-single-private-address-roam",
                    lambda: self.tcp_nat_netns_case("single-private-address-roam"),
                ),
                (
                    "tcp-nat44-half-open-recovery",
                    lambda: self.tcp_roaming_netns_case("half-open"),
                ),
                ("tcp-debug-hostile-stream", self.tcp_fault_injection_case),
            ]
        )

        if self.args.only_case:
            available = {name for name, _ in cases}
            requested = set(self.args.only_case)
            unknown = sorted(requested - available)
            if unknown:
                raise Failure(f"unknown --only-case value(s): {', '.join(unknown)}")
            cases = [(name, function) for name, function in cases if name in requested]

        try:
            if not self.host_transport_preflight():
                return 2
            for name, function in cases:
                try:
                    passed = self.run_case(name, function)
                except InfrastructureFailure as error:
                    self.abort_reason = str(error)
                    return 2
                if not passed and not self.args.keep_going:
                    break
        finally:
            self.write_report()
        return 1 if any(result["status"] != "PASS" for result in self.results) else 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--vm-a", default="wgtcp-a")
    result.add_argument("--vm-b", default="wgtcp-b")
    result.add_argument("--repo", default="/home/ubuntu/WireguardTCP")
    result.add_argument("--multipass", help="path to multipass.exe")
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
        return Suite(parser().parse_args()).run()
    except (Failure, OSError) as error:
        print(f"regression: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
