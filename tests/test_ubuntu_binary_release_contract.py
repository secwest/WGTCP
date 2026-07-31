from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
BUILD = (ROOT / "scripts" / "build-ubuntu-binary.sh").read_text(encoding="utf-8")
INSTALL = (ROOT / "scripts" / "install-ubuntu-binary.sh").read_text(
    encoding="utf-8"
)


class UbuntuBinaryReleaseContractTests(unittest.TestCase):
    def test_build_is_native_and_limited_to_supported_targets(self):
        self.assertIn("Ubuntu 24.04 is required", BUILD)
        self.assertIn("amd64|arm64", BUILD)
        self.assertIn("kernel_release=$(uname -r)", BUILD)
        self.assertIn("matching kernel headers are required", BUILD)

    def test_archive_contains_compiled_tree_module_tool_and_provenance(self):
        self.assertIn("compiled-tree", BUILD)
        self.assertIn("updates/wireguardtcp/wireguard.ko", BUILD)
        self.assertIn("$package/bin/wg", BUILD)
        self.assertIn('"source_revision": revision', BUILD)
        self.assertIn('sha256sum "$archive"', BUILD)

    def test_installer_rejects_wrong_os_architecture_and_kernel(self):
        self.assertIn('VERSION_ID:-} == "$expected_ubuntu"', INSTALL)
        self.assertIn('dpkg --print-architecture) == "$expected_arch"', INSTALL)
        self.assertIn('uname -r) == "$expected_kernel"', INSTALL)
        self.assertIn("sha256sum --check SHA256SUMS", INSTALL)

    def test_installer_refuses_active_interfaces_and_loads_payload(self):
        self.assertIn("ip -o link show type wireguard", INSTALL)
        self.assertIn("remove active WireGuard interfaces", INSTALL)
        self.assertIn('install -D -m 0644 "$module_source"', INSTALL)
        self.assertIn("modprobe wireguard", INSTALL)


if __name__ == "__main__":
    unittest.main()
