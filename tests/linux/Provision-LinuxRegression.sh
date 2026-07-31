#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

readonly OWNER="WireguardTCP tests/linux/Provision-LinuxRegression.sh"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
RESULTS_DIR=$SCRIPT_DIR/results
BASE_IMAGE=
SSH_PUBLIC_KEY=
SSH_PRIVATE_KEY=
STORAGE_DIR=/var/lib/libvirt/images/wireguardtcp-linux
VM_A=wgtcp-a
VM_B=wgtcp-b
PATH0_NETWORK=wgtcp-path0
PATH1_NETWORK=wgtcp-path1
CPU_COUNT=4
MEMORY_MIB=8192
DISK_SIZE=60G
RECREATE=0
FORCE_RECREATE_UNMANAGED=0
SKIP_GUEST_BUILD=0

die() {
	printf 'Provision-LinuxRegression: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: sudo tests/linux/Provision-LinuxRegression.sh --base-image IMAGE --ssh-public-key KEY --ssh-private-key KEY [options]

Options:
  --base-image PATH              Verified Ubuntu 24.04 cloud image (required)
  --ssh-public-key PATH          Public key authorized for the ubuntu guest user (required)
  --ssh-private-key PATH         Matching private key used while provisioning (required)
  --repo-root PATH               Git worktree to transfer (default: repository root)
  --results-dir PATH             Persistent harness state and logs
  --storage-dir PATH             Directory for VM disks and cloud-init seeds
  --vm-a NAME                    First libvirt domain name (default: wgtcp-a)
  --vm-b NAME                    Second libvirt domain name (default: wgtcp-b)
  --cpus COUNT                   vCPU count per VM (default: 4)
  --memory-mib MIB               Memory per VM in MiB (default: 8192)
  --disk-size SIZE               Per-VM overlay disk size (default: 60G)
  --recreate                     Recreate harness-owned domains
  --force-recreate-unmanaged     Permit --recreate to delete an unowned same-named domain
  --skip-guest-build             Transfer and bootstrap guests without compiling
  --help                         Show this help
EOF
}

while (( $# )); do
	case "$1" in
	--base-image) BASE_IMAGE=${2:?--base-image requires a value}; shift 2 ;;
	--ssh-public-key) SSH_PUBLIC_KEY=${2:?--ssh-public-key requires a value}; shift 2 ;;
	--ssh-private-key) SSH_PRIVATE_KEY=${2:?--ssh-private-key requires a value}; shift 2 ;;
	--repo-root) REPO_ROOT=${2:?--repo-root requires a value}; shift 2 ;;
	--results-dir) RESULTS_DIR=${2:?--results-dir requires a value}; shift 2 ;;
	--storage-dir) STORAGE_DIR=${2:?--storage-dir requires a value}; shift 2 ;;
	--vm-a) VM_A=${2:?--vm-a requires a value}; shift 2 ;;
	--vm-b) VM_B=${2:?--vm-b requires a value}; shift 2 ;;
	--cpus) CPU_COUNT=${2:?--cpus requires a value}; shift 2 ;;
	--memory-mib) MEMORY_MIB=${2:?--memory-mib requires a value}; shift 2 ;;
	--disk-size) DISK_SIZE=${2:?--disk-size requires a value}; shift 2 ;;
	--recreate) RECREATE=1; shift ;;
	--force-recreate-unmanaged) FORCE_RECREATE_UNMANAGED=1; shift ;;
	--skip-guest-build) SKIP_GUEST_BUILD=1; shift ;;
	--help) usage; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

(( EUID == 0 )) || die "run as root, for example: sudo $0 ..."
[[ -n $BASE_IMAGE ]] || die "--base-image is required"
[[ -n $SSH_PUBLIC_KEY ]] || die "--ssh-public-key is required"
[[ -n $SSH_PRIVATE_KEY ]] || die "--ssh-private-key is required"
[[ -f $BASE_IMAGE && -r $BASE_IMAGE ]] || die "base image is not readable: $BASE_IMAGE"
[[ -f $SSH_PUBLIC_KEY && -r $SSH_PUBLIC_KEY ]] || die "SSH public key is not readable: $SSH_PUBLIC_KEY"
[[ -f $SSH_PRIVATE_KEY && -r $SSH_PRIVATE_KEY ]] || die "SSH private key is not readable: $SSH_PRIVATE_KEY"
[[ -d $REPO_ROOT/.git ]] || die "not a Git worktree: $REPO_ROOT"
[[ $VM_A != "$VM_B" ]] || die "VM names must be distinct"
(( FORCE_RECREATE_UNMANAGED == 0 || RECREATE == 1 )) ||
	die "--force-recreate-unmanaged requires --recreate"
[[ $VM_A =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "unsafe VM name: $VM_A"
[[ $VM_B =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "unsafe VM name: $VM_B"
[[ $PATH0_NETWORK =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] ||
	die "unsafe network name: $PATH0_NETWORK"
[[ $PATH1_NETWORK =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] ||
	die "unsafe network name: $PATH1_NETWORK"
[[ $CPU_COUNT =~ ^[1-9][0-9]*$ ]] || die "--cpus must be a positive integer"
[[ $MEMORY_MIB =~ ^[1-9][0-9]*$ ]] || die "--memory-mib must be a positive integer"

for command in cloud-localds dnsmasq git qemu-img sha256sum ssh ssh-keygen scp tar virsh virt-install python3; do
	command -v "$command" >/dev/null || die "required host command was not found: $command"
done
if [[ ! -r /usr/share/seabios/bios-256k.bin &&
	! -r /usr/share/qemu/bios-256k.bin ]]; then
	die "SeaBIOS firmware was not found; install the seabios package"
fi

REPO_ROOT=$(cd -- "$REPO_ROOT" && pwd -P)
RESULTS_DIR=$(mkdir -p -- "$RESULTS_DIR"; cd -- "$RESULTS_DIR" && pwd -P)
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
	RESULTS_GROUP=$(id -gn "$SUDO_USER") ||
		die "could not resolve the results group for $SUDO_USER"
	chown "$SUDO_USER:$RESULTS_GROUP" "$RESULTS_DIR"
fi
STORAGE_DIR=$(mkdir -p -- "$STORAGE_DIR"; cd -- "$STORAGE_DIR" && pwd -P)
BASE_IMAGE=$(readlink -f -- "$BASE_IMAGE")
SSH_PUBLIC_KEY=$(readlink -f -- "$SSH_PUBLIC_KEY")
SSH_PRIVATE_KEY=$(readlink -f -- "$SSH_PRIVATE_KEY")
STATE_PATH=$RESULTS_DIR/provision-state.json
KNOWN_HOSTS_DIR=$RESULTS_DIR/known-hosts
mkdir -p -- "$KNOWN_HOSTS_DIR"

stage_base_image() {
	local source=$BASE_IMAGE hash staged temporary
	hash=$(sha256sum "$source" | awk '{print $1}')
	staged=$STORAGE_DIR/wireguardtcp-base-$hash.img
	if [[ -e $staged ]]; then
		[[ $(sha256sum "$staged" | awk '{print $1}') == "$hash" ]] ||
			die "staged base image checksum mismatch: $staged"
	else
		temporary=$(mktemp "$STORAGE_DIR/.wireguardtcp-base.XXXXXX")
		cp --reflink=auto --sparse=always -- "$source" "$temporary"
		[[ $(sha256sum "$temporary" | awk '{print $1}') == "$hash" ]] || {
			rm -f -- "$temporary"
			die "staged base image checksum verification failed"
		}
		chmod 0644 "$temporary"
		mv -- "$temporary" "$staged"
	fi
	chmod 0644 "$staged"
	BASE_IMAGE=$staged
}

readonly PATH0_A_MAC=52:54:00:10:00:0a
readonly PATH0_B_MAC=52:54:00:10:00:0b
readonly PATH1_A_MAC=52:54:00:20:00:0a
readonly PATH1_B_MAC=52:54:00:20:00:0b
readonly MGMT_A_MAC=52:54:00:30:00:0a
readonly MGMT_B_MAC=52:54:00:30:00:0b
readonly PATH0_A_ADDRESS=10.77.0.10
readonly PATH0_B_ADDRESS=10.77.0.11
readonly PATH1_A_ADDRESS=10.77.1.10
readonly PATH1_B_ADDRESS=10.77.1.11

virsh_qemu() {
	virsh -c qemu:///system "$@"
}

domain_exists() {
	virsh_qemu dominfo "$1" >/dev/null 2>&1
}

network_exists() {
	virsh_qemu net-info "$1" >/dev/null 2>&1
}

state_identity() {
	local kind=$1 name=$2
	[[ -r $STATE_PATH ]] || return 0
	python3 - "$STATE_PATH" "$kind" "$name" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
for record in document.get(sys.argv[2], []):
    if record.get("Name") == sys.argv[3]:
        print(record.get("Uuid", ""))
        break
PY
}

validate_state() {
	[[ -r $STATE_PATH ]] || return 0
	python3 - "$STATE_PATH" "$OWNER" "$VM_A" "$VM_B" "$PATH0_NETWORK" "$PATH1_NETWORK" <<'PY'
import json
import sys

path, owner, vm_a, vm_b, network_a, network_b = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)
if document.get("Owner") != owner:
    raise SystemExit(f"unexpected provisioning state owner: {document.get('Owner')!r}")
configuration = document.get("Configuration", {})
if configuration.get("VmNames") != [vm_a, vm_b]:
    raise SystemExit("provisioning state VM names differ from the requested lab")
if configuration.get("Networks") != [network_a, network_b]:
    raise SystemExit("provisioning state network names differ from the requested lab")
PY
}

write_state() {
	local status=$1 snapshot_manifest=${2:-}
	STATE_OWNER=$OWNER \
	STATE_STATUS=$status \
	STATE_VM_A=$VM_A STATE_VM_B=$VM_B \
	STATE_PATH0_NETWORK=$PATH0_NETWORK STATE_PATH1_NETWORK=$PATH1_NETWORK \
	STATE_VM_A_UUID=$(domain_exists "$VM_A" && virsh_qemu domuuid "$VM_A" || true) \
	STATE_VM_B_UUID=$(domain_exists "$VM_B" && virsh_qemu domuuid "$VM_B" || true) \
	STATE_PATH0_UUID=$(network_exists "$PATH0_NETWORK" && virsh_qemu net-uuid "$PATH0_NETWORK" || true) \
	STATE_PATH1_UUID=$(network_exists "$PATH1_NETWORK" && virsh_qemu net-uuid "$PATH1_NETWORK" || true) \
	STATE_VM_A_DISK=$STORAGE_DIR/$VM_A.qcow2 \
	STATE_VM_B_DISK=$STORAGE_DIR/$VM_B.qcow2 \
	STATE_VM_A_SEED=$STORAGE_DIR/$VM_A-seed.img \
	STATE_VM_B_SEED=$STORAGE_DIR/$VM_B-seed.img \
	STATE_SNAPSHOT_MANIFEST=$snapshot_manifest \
	python3 - "$STATE_PATH" "$STATE_PATH.tmp" <<'PY'
import datetime
import json
import os
import pathlib
import sys

path, temporary = map(pathlib.Path, sys.argv[1:])
env = os.environ
guests = []
for name, path0_address, path1_address, path0_mac, path1_mac, management_mac in (
    (
        env["STATE_VM_A"],
        "10.77.0.10",
        "10.77.1.10",
        "52:54:00:10:00:0a",
        "52:54:00:20:00:0a",
        "52:54:00:30:00:0a",
    ),
    (
        env["STATE_VM_B"],
        "10.77.0.11",
        "10.77.1.11",
        "52:54:00:10:00:0b",
        "52:54:00:20:00:0b",
        "52:54:00:30:00:0b",
    ),
):
    guests.append(
        {
            "Name": name,
            "Path0Address": path0_address,
            "Path1Address": path1_address,
            "Path0Mac": path0_mac,
            "Path1Mac": path1_mac,
            "ManagementMac": management_mac,
        }
    )
document = {
    "Schema": 1,
    "Owner": env["STATE_OWNER"],
    "UpdatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "Status": env["STATE_STATUS"],
    "Configuration": {
        "VmNames": [env["STATE_VM_A"], env["STATE_VM_B"]],
        "Networks": [env["STATE_PATH0_NETWORK"], env["STATE_PATH1_NETWORK"]],
        "Guests": guests,
    },
    "VmIdentities": [
        {
            "Name": env["STATE_VM_A"],
            "Uuid": env["STATE_VM_A_UUID"],
            "Disk": env["STATE_VM_A_DISK"],
            "Seed": env["STATE_VM_A_SEED"],
        },
        {
            "Name": env["STATE_VM_B"],
            "Uuid": env["STATE_VM_B_UUID"],
            "Disk": env["STATE_VM_B_DISK"],
            "Seed": env["STATE_VM_B_SEED"],
        },
    ],
    "NetworkIdentities": [
        {"Name": env["STATE_PATH0_NETWORK"], "Uuid": env["STATE_PATH0_UUID"]},
        {"Name": env["STATE_PATH1_NETWORK"], "Uuid": env["STATE_PATH1_UUID"]},
    ],
}
manifest = env.get("STATE_SNAPSHOT_MANIFEST")
if manifest:
    with open(manifest, encoding="utf-8") as stream:
        document["Snapshot"] = json.load(stream)
with open(temporary, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2)
    stream.write("\n")
os.replace(temporary, path)
PY
}

assert_managed_domain() {
	local name=$1 live expected
	live=$(virsh_qemu domuuid "$name")
	expected=$(state_identity VmIdentities "$name")
	[[ -n $expected ]] || die "domain '$name' exists without a persisted managed UUID; refusing to adopt it"
	[[ $live == "$expected" ]] ||
		die "domain '$name' UUID '$live' does not match managed UUID '$expected'; refusing to modify it"
}

assert_managed_network() {
	local name=$1 live expected xml
	live=$(virsh_qemu net-uuid "$name")
	expected=$(state_identity NetworkIdentities "$name")
	[[ -n $expected ]] || die "network '$name' exists without a persisted managed UUID; refusing to adopt it"
	[[ $live == "$expected" ]] ||
		die "network '$name' UUID '$live' does not match managed UUID '$expected'; refusing to modify it"
	xml=$(virsh_qemu net-dumpxml "$name")
	if grep -q '<forward' <<<"$xml" &&
		! grep -Eq "<forward[^>]+mode=['\"]none['\"]" <<<"$xml"; then
		die "managed network '$name' is not isolated (forward mode none)"
	fi
}

destroy_domain() {
	local name=$1 disk=$STORAGE_DIR/$1.qcow2 seed=$STORAGE_DIR/$1-seed.img
	assert_managed_domain "$name"
	if [[ $(virsh_qemu domstate "$name") != "shut off" ]]; then
		virsh_qemu destroy "$name" >/dev/null
	fi
	virsh_qemu undefine "$name" --managed-save --snapshots-metadata --nvram >/dev/null
	rm -f -- "$disk" "$seed"
}

ensure_network() {
	local name=$1 bridge=$2 xml expected
	if network_exists "$name"; then
		assert_managed_network "$name"
	else
		expected=$(state_identity NetworkIdentities "$name")
		[[ -z $expected ]] ||
			die "managed network '$name' with UUID '$expected' is missing; refusing to replace it implicitly"
		xml=$(mktemp "$RESULTS_DIR/$name.XXXXXX.xml")
		cat >"$xml" <<EOF
<network>
  <name>$name</name>
  <forward mode='none'/>
  <bridge name='$bridge' stp='on' delay='0'/>
</network>
EOF
		virsh_qemu net-define "$xml" >/dev/null
		rm -f -- "$xml"
		virsh_qemu net-autostart "$name" >/dev/null
		write_state Provisioning
	fi
	if [[ $(virsh_qemu net-info "$name" | awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print $2 }') != "yes" ]]; then
		virsh_qemu net-start "$name" >/dev/null
	fi
}

render_cloud_init() {
	local name=$1 management_mac=$2 path0_mac=$3 path0_address=$4 path1_mac=$5 path1_address=$6
	local user_data=$STORAGE_DIR/$name-user-data.yaml
	local network_data=$STORAGE_DIR/$name-network-data.yaml
	local metadata=$STORAGE_DIR/$name-meta-data.yaml
	local seed=$STORAGE_DIR/$name-seed.img
	local public_key
	public_key=$(<"$SSH_PUBLIC_KEY")
	[[ $public_key == ssh-* ]] || die "SSH public key does not look like an OpenSSH public key"
	cat >"$user_data" <<EOF
#cloud-config
users:
  - name: ubuntu
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
EOF
	cat >"$network_data" <<EOF
version: 2
ethernets:
  management:
    match:
      macaddress: "$management_mac"
    set-name: management
    dhcp4: true
    dhcp6: false
  path0:
    match:
      macaddress: "$path0_mac"
    set-name: path0
    dhcp4: false
    dhcp6: false
    addresses: ["$path0_address/24"]
  path1:
    match:
      macaddress: "$path1_mac"
    set-name: path1
    dhcp4: false
    dhcp6: false
    addresses: ["$path1_address/24"]
EOF
	cat >"$metadata" <<EOF
instance-id: wireguardtcp-$name
local-hostname: $name
EOF
	cloud-localds --network-config "$network_data" "$seed" "$user_data" "$metadata"
	chmod 0644 "$seed"
	rm -f -- "$user_data" "$network_data" "$metadata"
}

create_domain() {
	local name=$1 management_mac=$2 path0_mac=$3 path0_address=$4 path1_mac=$5 path1_address=$6
	local disk=$STORAGE_DIR/$name.qcow2 seed=$STORAGE_DIR/$name-seed.img base_format
	[[ ! -e $disk && ! -e $seed ]] ||
		die "refusing to overwrite existing disk or seed for unprovisioned domain '$name'"
	base_format=$(qemu-img info --output=json "$BASE_IMAGE" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["format"])')
	qemu-img create -q -f qcow2 -F "$base_format" -b "$BASE_IMAGE" "$disk" "$DISK_SIZE"
	render_cloud_init "$name" "$management_mac" "$path0_mac" "$path0_address" "$path1_mac" "$path1_address"
	if ! virt-install --connect qemu:///system \
		--name "$name" \
		--memory "$MEMORY_MIB" \
		--vcpus "$CPU_COUNT" \
		--import \
		--os-variant ubuntu24.04 \
		--disk "path=$disk,format=qcow2,bus=virtio" \
		--disk "path=$seed,device=cdrom,readonly=on" \
		--network "network=default,mac=$management_mac,model=virtio" \
		--network "network=$PATH0_NETWORK,mac=$path0_mac,model=virtio" \
		--network "network=$PATH1_NETWORK,mac=$path1_mac,model=virtio" \
		--graphics none \
		--noautoconsole; then
		rm -f -- "$disk" "$seed"
		die "virt-install failed while creating '$name'"
	fi
	if virsh_qemu dumpxml "$name" | grep -q '<loader'; then
		virsh_qemu destroy "$name" >/dev/null 2>&1 || true
		virsh_qemu undefine "$name" --nvram >/dev/null 2>&1 || true
		rm -f -- "$disk" "$seed"
		die "domain '$name' selected UEFI; refusing to run unsigned test modules"
	fi
	write_state Provisioning
}

ensure_domain() {
	local name=$1 management_mac=$2 path0_mac=$3 path0_address=$4 path1_mac=$5 path1_address=$6 expected
	expected=$(state_identity VmIdentities "$name")
	if domain_exists "$name"; then
		if [[ $RECREATE == 1 ]]; then
			if [[ -n $(state_identity VmIdentities "$name") ]]; then
				destroy_domain "$name"
			elif [[ $FORCE_RECREATE_UNMANAGED == 1 ]]; then
				printf 'Provision-LinuxRegression: deleting explicitly approved unmanaged domain %s\n' "$name" >&2
				if [[ $(virsh_qemu domstate "$name") != "shut off" ]]; then
					virsh_qemu destroy "$name" >/dev/null
				fi
				virsh_qemu undefine "$name" --managed-save --snapshots-metadata --nvram >/dev/null
			else
				die "domain '$name' exists without a managed UUID; use --recreate --force-recreate-unmanaged only after verifying it is disposable"
			fi
		else
			assert_managed_domain "$name"
		fi
	elif [[ -n $expected && $RECREATE == 0 ]]; then
		die "managed domain '$name' with UUID '$expected' is missing; use --recreate to intentionally replace it"
	fi
	if ! domain_exists "$name"; then
		rm -f -- "$KNOWN_HOSTS_DIR/$name"
		create_domain "$name" "$management_mac" "$path0_mac" "$path0_address" "$path1_mac" "$path1_address"
	elif [[ $(virsh_qemu domstate "$name") == "shut off" ]]; then
		virsh_qemu start "$name" >/dev/null
	fi
}

domain_ip() {
	local name=$1
	virsh_qemu domifaddr "$name" --source lease 2>/dev/null |
		awk '$3 == "ipv4" { split($4, address, "/"); print address[1]; exit }'
}

wait_for_ssh() {
	local name=$1 address deadline known_hosts
	known_hosts=$KNOWN_HOSTS_DIR/$name
	deadline=$(( SECONDS + 600 ))
	while (( SECONDS < deadline )); do
		address=$(domain_ip "$name" || true)
		if [[ -n $address ]] && ssh \
			-i "$SSH_PRIVATE_KEY" \
			-o BatchMode=yes \
			-o ConnectTimeout=10 \
			-o StrictHostKeyChecking=accept-new \
			-o "UserKnownHostsFile=$known_hosts" \
			"ubuntu@$address" true >/dev/null 2>&1; then
			printf '%s\n' "$address"
			return
		fi
		sleep 5
	done
	die "timed out waiting for SSH to '$name'"
}

ssh_guest() {
	local address=$1
	shift
	ssh -o BatchMode=yes -o ConnectTimeout=30 -o StrictHostKeyChecking=yes \
		-i "$SSH_PRIVATE_KEY" \
		-o "UserKnownHostsFile=$KNOWN_HOSTS_DIR/$CURRENT_GUEST" \
		"ubuntu@$address" "$@"
}

create_snapshot() {
	local snapshot_dir status_before status_after base overlay modified untracked overlay_files deletions manifest
	snapshot_dir=$(mktemp -d "$RESULTS_DIR/snapshot.XXXXXX")
	base=$snapshot_dir/base.tar
	overlay=$snapshot_dir/overlay.tar
	modified=$snapshot_dir/modified.zlist
	untracked=$snapshot_dir/untracked.zlist
	overlay_files=$snapshot_dir/overlay-files.zlist
	deletions=$snapshot_dir/deletions.zlist
	manifest=$snapshot_dir/snapshot-manifest.json
	status_before=$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		status --porcelain=v2 --branch --untracked-files=all)
	git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		archive --format=tar --output="$base" HEAD
	git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		-c core.safecrlf=false diff --name-only --no-renames \
		--diff-filter=ACMRTUXB -z HEAD -- >"$modified"
	git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		ls-files --others --exclude-standard -z >"$untracked"
	cat "$modified" "$untracked" | sort -zu >"$overlay_files"
	if [[ -s $overlay_files ]]; then
		(
			cd -- "$REPO_ROOT"
			tar --null --verbatim-files-from --format=pax -cf "$overlay" -T "$overlay_files"
		)
	else
		tar --format=pax -cf "$overlay" --files-from /dev/null
	fi
	git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		-c core.safecrlf=false diff --name-only --no-renames \
		--diff-filter=D -z HEAD -- >"$deletions"
	status_after=$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" \
		status --porcelain=v2 --branch --untracked-files=all)
	[[ $status_before == "$status_after" ]] ||
		die "the worktree changed while the guest snapshot was being built; run provisioning again"
	SNAPSHOT_DIR=$snapshot_dir SNAPSHOT_BASE=$base SNAPSHOT_OVERLAY=$overlay \
	SNAPSHOT_DELETIONS=$deletions SNAPSHOT_STATUS=$status_before \
	python3 - "$manifest" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

destination = pathlib.Path(sys.argv[1])
base = pathlib.Path(os.environ["SNAPSHOT_BASE"])
overlay = pathlib.Path(os.environ["SNAPSHOT_OVERLAY"])
document = {
    "Schema": 1,
    "CreatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "Head": subprocess.check_output(
        [
            "git",
            "-c",
            f"safe.directory={os.environ['REPO_ROOT']}",
            "-C",
            os.environ["REPO_ROOT"],
            "rev-parse",
            "HEAD",
        ],
        text=True,
    ).strip(),
    "GitStatus": os.environ["SNAPSHOT_STATUS"],
    "BaseArchive": base.name,
    "BaseArchiveSha256": sha256(base),
    "OverlayArchive": overlay.name,
    "OverlayArchiveSha256": sha256(overlay),
    "Deletions": pathlib.Path(os.environ["SNAPSHOT_DELETIONS"]).name,
}
destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PY
	SNAPSHOT_DIR=$snapshot_dir
	SNAPSHOT_BASE=$base
	SNAPSHOT_OVERLAY=$overlay
	SNAPSHOT_DELETIONS=$deletions
	SNAPSHOT_MANIFEST=$manifest
	SNAPSHOT_ID=$(sha256sum "$overlay" | awk '{print substr($1, 1, 12)}')
}

install_snapshot() {
	local name=$1 address=$2 remote=/home/ubuntu/.wgtcp-transfer-$SNAPSHOT_ID
	CURRENT_GUEST=$name
	ssh_guest "$address" mkdir -p "$remote"
	scp -o BatchMode=yes -o ConnectTimeout=30 -o StrictHostKeyChecking=yes \
		-i "$SSH_PRIVATE_KEY" \
		-o "UserKnownHostsFile=$KNOWN_HOSTS_DIR/$name" \
		"$SNAPSHOT_BASE" "$SNAPSHOT_OVERLAY" "$SNAPSHOT_DELETIONS" "$SNAPSHOT_MANIFEST" \
		"ubuntu@$address:$remote/"
	ssh_guest "$address" sudo bash -s -- "$remote" "$SNAPSHOT_ID" \
		"$(sha256sum "$SNAPSHOT_BASE" | awk '{print $1}')" \
		"$(sha256sum "$SNAPSHOT_OVERLAY" | awk '{print $1}')" <<'REMOTE'
set -Eeuo pipefail
transfer=$1
snapshot_id=$2
base_hash=$3
overlay_hash=$4
repo=/home/ubuntu/WireguardTCP
stage=/home/ubuntu/.wgtcp-stage-$snapshot_id
previous=/home/ubuntu/.wgtcp-previous
printf '%s  %s\n%s  %s\n' "$base_hash" "$transfer/base.tar" \
	"$overlay_hash" "$transfer/overlay.tar" | sha256sum -c -
rm -rf -- "$stage"
mkdir -p -- "$stage"
tar -xf "$transfer/base.tar" -C "$stage"
while IFS= read -r -d '' relative; do
	[[ -z $relative ]] && continue
	case "$relative" in
	.|..|/*|../*|*/../*|*/..) printf 'unsafe deletion path: %s\n' "$relative" >&2; exit 1 ;;
	esac
	rm -rf -- "$stage/$relative"
done <"$transfer/deletions.zlist"
tar --unlink-first -xf "$transfer/overlay.tar" -C "$stage"
rm -rf -- "$previous"
if [[ -e $repo ]]; then
	mv -- "$repo" "$previous"
fi
mv -- "$stage" "$repo"
cp -- "$transfer/snapshot-manifest.json" /home/ubuntu/.wgtcp-current-snapshot.json
REMOTE
}

validate_state
stage_base_image
virsh_qemu uri >/dev/null
virsh_qemu net-info default >/dev/null 2>&1 || die "the libvirt default management network is missing"
[[ $(virsh_qemu net-info default | awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print $2 }') == yes ]] ||
	die "the libvirt default management network must be active"

ensure_network "$PATH0_NETWORK" wgtcp-path0
ensure_network "$PATH1_NETWORK" wgtcp-path1
write_state Provisioning

ensure_domain "$VM_A" "$MGMT_A_MAC" "$PATH0_A_MAC" "$PATH0_A_ADDRESS" "$PATH1_A_MAC" "$PATH1_A_ADDRESS"
ensure_domain "$VM_B" "$MGMT_B_MAC" "$PATH0_B_MAC" "$PATH0_B_ADDRESS" "$PATH1_B_MAC" "$PATH1_B_ADDRESS"
write_state Provisioning

address_a=$(wait_for_ssh "$VM_A")
address_b=$(wait_for_ssh "$VM_B")
for guest in "$VM_A" "$VM_B"; do
	CURRENT_GUEST=$guest
	address=$address_a
	[[ $guest == "$VM_B" ]] && address=$address_b
	path0_address=$PATH0_A_ADDRESS
	path1_address=$PATH1_A_ADDRESS
	if [[ $guest == "$VM_B" ]]; then
		path0_address=$PATH0_B_ADDRESS
		path1_address=$PATH1_B_ADDRESS
	fi
	ssh_guest "$address" ip -4 -o address show dev path0 |
		grep -F -- " $path0_address/24 "
	ssh_guest "$address" ip -4 -o address show dev path1 |
		grep -F -- " $path1_address/24 "
done

export REPO_ROOT
create_snapshot
for guest in "$VM_A" "$VM_B"; do
	CURRENT_GUEST=$guest
	address=$address_a
	[[ $guest == "$VM_B" ]] && address=$address_b
	printf '[source] Installing snapshot on %s\n' "$guest"
	install_snapshot "$guest" "$address"
	printf '[bootstrap] Preparing %s\n' "$guest"
	ssh_guest "$address" sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-bootstrap.sh
	if [[ $SKIP_GUEST_BUILD == 0 ]]; then
		printf '[build] Compiling tools and modules on %s\n' "$guest"
		ssh_guest "$address" sudo bash /home/ubuntu/WireguardTCP/tests/hyperv/guest-build.sh
	fi
done

write_state Ready "$SNAPSHOT_MANIFEST"
cat "$STATE_PATH"
