from pathlib import Path
import unittest


PROVISION = (
    Path(__file__).parent / "linux" / "Provision-LinuxRegression.sh"
).read_text(encoding="utf-8")


class LinuxProvisionContractTests(unittest.TestCase):
    def test_provisioner_uses_two_isolated_libvirt_networks(self):
        self.assertIn("<forward mode='none'/>", PROVISION)
        self.assertIn("PATH0_NETWORK=wgtcp-path0", PROVISION)
        self.assertIn("PATH1_NETWORK=wgtcp-path1", PROVISION)
        self.assertIn('--network "network=$PATH0_NETWORK,mac=$path0_mac,model=virtio"', PROVISION)
        self.assertIn('--network "network=$PATH1_NETWORK,mac=$path1_mac,model=virtio"', PROVISION)

    def test_unsigned_test_module_is_not_blocked_by_secure_boot(self):
        self.assertIn("--boot bios", PROVISION)

    def test_provisioner_records_and_rechecks_resource_identity(self):
        self.assertIn('"VmIdentities"', PROVISION)
        self.assertIn('"NetworkIdentities"', PROVISION)
        self.assertIn("refusing to adopt", PROVISION)
        self.assertIn("refusing to replace it implicitly", PROVISION)

    def test_source_snapshot_and_guest_build_are_required(self):
        self.assertIn("git -C \"$REPO_ROOT\" archive", PROVISION)
        self.assertIn("BaseArchiveSha256", PROVISION)
        self.assertIn("OverlayArchiveSha256", PROVISION)
        self.assertIn("guest-bootstrap.sh", PROVISION)
        self.assertIn("guest-build.sh", PROVISION)


if __name__ == "__main__":
    unittest.main()
