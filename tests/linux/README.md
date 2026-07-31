# Linux libvirt regression lab

This directory provides the Linux-host equivalent of the Hyper-V regression
lab. It provisions two Ubuntu 24.04 QEMU/KVM guests through system libvirt:

| Guest | Resources | `path0` | `path1` |
| --- | --- | --- | --- |
| `wgtcp-a` | 4 vCPU, 8 GiB RAM, 60 GiB overlay disk | `10.77.0.10/24` | `10.77.1.10/24` |
| `wgtcp-b` | 4 vCPU, 8 GiB RAM, 60 GiB overlay disk | `10.77.0.11/24` | `10.77.1.11/24` |

Each guest also connects to libvirt's existing `default` network for package
installation and host control. `wgtcp-path0` and `wgtcp-path1` are isolated
libvirt networks with no forwarding. The runner uses SSH on the management
network while the suite exercises the two private carrier paths.

## Prerequisites

Use an Ubuntu 24.04-or-newer Linux KVM host with hardware virtualization
available to QEMU. Install the existing distribution packages:

```bash
sudo apt-get update
sudo apt-get install --yes \
  qemu-kvm qemu-utils seabios libvirt-daemon-system libvirt-clients \
  virtinst cloud-image-utils dnsmasq-base openssh-client python3 ubuntu-keyring
sudo systemctl enable --now libvirtd
sudo virsh -c qemu:///system net-start default
```

The host needs at least 16 GiB free RAM and 120 GiB free disk. Obtain the
Ubuntu 24.04 cloud image from Canonical and verify it before provision. The
provisioner deliberately requires a local image instead of downloading an
unverified moving image:

```bash
curl -fLO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
curl -fLO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg
curl -fLO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg \
  SHA256SUMS.gpg SHA256SUMS
grep ' [*]noble-server-cloudimg-amd64.img$' SHA256SUMS | sha256sum --check
```

Supply an SSH public key that belongs to the account which will run the
regression command. The private key must be available to that account's
OpenSSH client.

## Provision and run

From the repository root:

```bash
sudo ./tests/linux/Provision-LinuxRegression.sh \
  --base-image "$PWD/noble-server-cloudimg-amd64.img" \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --ssh-private-key "$HOME/.ssh/id_ed25519"

./tests/linux/Run-LinuxRegression.sh
```

Provisioning records the libvirt domain and network UUIDs in
`tests/linux/results/provision-state.json`; a same-named resource without the
recorded UUID is never adopted or changed. It creates a Git-visible snapshot
from `HEAD`, modified/untracked overlays, and recorded deletions, verifies both
archive hashes in each guest, runs the shared bootstrap, and compiles the
production, DEBUG, and fault-injection modules on each guest. The provisioner
copies the verified cloud image into libvirt storage so QEMU can read its
backing image even when the original is beneath a private home directory.

The full runner delegates to the same case list and guest helpers as
`tests/hyperv/regression.py`, so it runs the complete 36-case matrix. Results
are written beneath `tests/linux/results/runs/`. Select a focused case by
passing runner arguments after `--`:

```bash
./tests/linux/Run-LinuxRegression.sh -- \
  --only-case tcp-nat44-dual-reachable
```

To deliberately rebuild only the harness-owned domains, run the provisioner
again with `--recreate`. A same-named domain that lacks a matching recorded UUID
requires the separate `--force-recreate-unmanaged` acknowledgement.

## Cleanup

The provisioner does not delete virtual machines or networks implicitly. Read
the persisted UUIDs before cleanup, then verify and remove only the matching
resources:

```bash
state=tests/linux/results/provision-state.json
sudo virsh -c qemu:///system domuuid wgtcp-a
sudo virsh -c qemu:///system domuuid wgtcp-b
sudo virsh -c qemu:///system net-uuid wgtcp-path0
sudo virsh -c qemu:///system net-uuid wgtcp-path1
```

Only after each value matches the corresponding `VmIdentities` or
`NetworkIdentities` entry in `$state`, destroy and undefine the two domains,
then destroy and undefine the two private networks. Do not remove the libvirt
`default` network. The harness-owned disk overlays and cloud-init seeds are
under `/var/lib/libvirt/images/wireguardtcp-linux/`.
