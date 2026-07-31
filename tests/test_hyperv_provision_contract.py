from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent
PROVISION = (ROOT / "hyperv" / "Provision-HyperV.ps1").read_text(encoding="utf-8")
SETUP = (ROOT / "hyperv" / "HYPERV_SETUP.md").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    match = re.search(
        rf"(?ms)^function {re.escape(name)} \{{(?P<body>.*?)(?=^function |^foreach \(\$guest in \$guests\))",
        PROVISION,
    )
    if match is None:
        raise AssertionError(f"function not found: {name}")
    return match.group("body")


class HyperVProvisionContractTests(unittest.TestCase):
    def test_schema_two_persists_vm_and_switch_guids(self):
        writer = function_body("Write-ManagedState")

        self.assertIn("Schema = 2", writer)
        self.assertIn("VmIdentities = @(", writer)
        self.assertIn("SwitchIdentities = @(", writer)
        self.assertIn("HyperVSwitchId", PROVISION)

    def test_existing_switch_requires_recorded_identity(self):
        ensure = function_body("Ensure-PrivateSwitch")

        self.assertIn("Assert-HyperVSwitchIdentity", ensure)
        self.assertIn("without a persisted managed switch ID", ensure)
        self.assertIn("Refusing to replace it implicitly", ensure)

    def test_legacy_switch_migration_requires_exact_managed_topology(self):
        migration = function_body("Assert-LegacyPrivateSwitchTopology")

        self.assertIn("Get-VMNetworkAdapter -All", migration)
        self.assertIn("$adapters.Count -ne $guests.Count", migration)
        self.assertIn("Assert-HyperVVmIdentity", migration)
        self.assertIn("$matches.Count -ne 1", migration)

    def test_switch_ids_are_rechecked_before_adapter_changes(self):
        configure = function_body("Ensure-GuestVmConfiguration")

        self.assertGreaterEqual(configure.count("Assert-HyperVSwitchIdentity"), 4)
        self.assertIn("ExpectedPath0SwitchId", configure)
        self.assertIn("ExpectedPath1SwitchId", configure)

    def test_guest_stop_is_bounded_without_misusing_multipass_time(self):
        stop = function_body("Stop-MultipassInstance")
        configure = function_body("Ensure-GuestVmConfiguration")

        self.assertIn('-ArgumentList @("stop", $Name)', stop)
        self.assertIn("WaitForExit($TimeoutSeconds * 1000)", stop)
        self.assertIn("Stop-Process -Id $process.Id", stop)
        self.assertIn("only client PID", stop)
        self.assertIn("Stop-MultipassInstance -Name $Name", configure)
        self.assertNotIn('@("stop", "--timeout"', PROVISION)

    def test_guest_build_retains_guest_and_host_transcripts(self):
        build = function_body("Invoke-MultipassGuestBuild")

        self.assertIn('"/tmp/wgtcp-build.log"', build)
        self.assertIn('("guest-build-{0}.log" -f $Name)', build)
        self.assertIn("set -o pipefail", build)
        self.assertIn("2>&1 | tee $guestLogPath", build)
        self.assertIn("[System.IO.File]::WriteAllLines", build)
        self.assertIn("[System.IO.File]::WriteAllText", build)
        self.assertIn("Invoke-MultipassGuestBuild -Name $guest.Name", PROVISION)

    def test_vm_worker_recovery_rechecks_cim_and_vm_identity(self):
        recovery = SETUP.split("### Exceptional stuck VM worker recovery", 1)[1]
        recovery = recovery.split("### Management SSH wait", 1)[0]

        self.assertGreaterEqual(recovery.count("Get-VM -Name $name"), 2)
        self.assertIn('Get-CimInstance Win32_Process -Filter "ProcessId=$workerPid"', recovery)
        self.assertIn("$workerAgain[0].CommandLine -notmatch $idPattern", recovery)
        self.assertLess(recovery.rfind("$workerAgain"), recovery.rfind("Stop-Process"))


if __name__ == "__main__":
    unittest.main()
