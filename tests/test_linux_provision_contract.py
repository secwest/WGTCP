from pathlib import Path
import unittest


PROVISION = (
    Path(__file__).parent / "linux" / "Provision-LinuxRegression.sh"
).read_text(encoding="utf-8")
KERNEL_MAKEFILE = (
    Path(__file__).parents[1] / "kernel" / "Makefile"
).read_text(encoding="utf-8")


class LinuxProvisionContractTests(unittest.TestCase):
    def test_default_resource_names_use_bash_compatible_validation(self):
        self.assertNotIn("(?:", PROVISION)
        self.assertIn("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", PROVISION)

    def test_libvirt_management_network_dependency_is_required(self):
        self.assertIn("cloud-localds dnsmasq git", PROVISION)

    def test_provisioner_uses_two_isolated_libvirt_networks(self):
        self.assertIn("<forward mode='none'/>", PROVISION)
        self.assertIn("PATH0_NETWORK=wgtcp-path0", PROVISION)
        self.assertIn("PATH1_NETWORK=wgtcp-path1", PROVISION)
        self.assertIn('--network "network=$PATH0_NETWORK,mac=$path0_mac,model=virtio"', PROVISION)
        self.assertIn('--network "network=$PATH1_NETWORK,mac=$path1_mac,model=virtio"', PROVISION)

    def test_unsigned_test_module_is_not_blocked_by_secure_boot(self):
        self.assertNotIn("--boot uefi", PROVISION)
        self.assertIn("virsh_qemu dumpxml \"$name\" | grep -q '<loader'", PROVISION)
        self.assertIn("refusing to run unsigned test modules", PROVISION)
        self.assertIn("install the seabios package", PROVISION)

    def test_provisioner_records_and_rechecks_resource_identity(self):
        self.assertIn('"VmIdentities"', PROVISION)
        self.assertIn('"NetworkIdentities"', PROVISION)
        self.assertIn("refusing to adopt", PROVISION)
        self.assertIn("refusing to replace it implicitly", PROVISION)

    def test_source_snapshot_and_guest_build_are_required(self):
        self.assertIn("archive --format=tar", PROVISION)
        self.assertIn("BaseArchiveSha256", PROVISION)
        self.assertIn("OverlayArchiveSha256", PROVISION)
        self.assertIn("guest-bootstrap.sh", PROVISION)
        self.assertIn("guest-build.sh", PROVISION)

    def test_split_tcp_debug_source_is_linked_into_the_module(self):
        self.assertIn("wireguard-y += wg_tcp_debug.o", KERNEL_MAKEFILE)

    def test_root_snapshot_scopes_git_safe_directory_to_the_requested_repo(self):
        self.assertGreaterEqual(PROVISION.count('safe.directory="$REPO_ROOT"'), 6)
        self.assertIn("safe.directory={os.environ['REPO_ROOT']}", PROVISION)

    def test_root_provisioner_uses_the_callers_explicit_private_key(self):
        self.assertIn("--ssh-private-key", PROVISION)
        self.assertGreaterEqual(PROVISION.count('-i "$SSH_PRIVATE_KEY"'), 3)
        self.assertIn('"SshPrivateKey": env["STATE_SSH_PRIVATE_KEY"]', PROVISION)

    def test_provisioner_probes_all_reported_dhcp_leases(self):
        self.assertIn("domain_ips()", PROVISION)
        self.assertIn("if (!seen[address[1]]++)", PROVISION)
        self.assertIn('for address in "${addresses[@]}"; do', PROVISION)
        self.assertIn('"ubuntu@$address" true', PROVISION)

    def test_verified_base_image_is_staged_for_libvirt_access(self):
        self.assertIn("stage_base_image()", PROVISION)
        self.assertIn('sha256sum "$source"', PROVISION)
        self.assertIn('chmod 0644 "$staged"', PROVISION)
        self.assertIn("BASE_IMAGE=$staged", PROVISION)

    def test_results_directory_is_returned_to_the_sudo_caller(self):
        self.assertIn("${SUDO_USER:-}", PROVISION)
        self.assertIn('chown "$SUDO_USER:$RESULTS_GROUP" "$RESULTS_DIR"', PROVISION)


if __name__ == "__main__":
    unittest.main()
