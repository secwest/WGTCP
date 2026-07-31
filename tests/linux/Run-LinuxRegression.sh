#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
RESULTS_DIR=$SCRIPT_DIR/results

die() {
	printf 'Run-LinuxRegression: %s\n' "$*" >&2
	exit 1
}

while (( $# )); do
	case "$1" in
	--results-dir)
		(( $# >= 2 )) || die "--results-dir requires a value"
		RESULTS_DIR=$2
		shift 2
		;;
	--)
		shift
		break
		;;
	*)
		break
		;;
	esac
done

STATE_PATH=$RESULTS_DIR/provision-state.json
[[ -r $STATE_PATH ]] || die "provisioning state not found: $STATE_PATH"
command -v virsh >/dev/null || die "virsh is required"
command -v python3 >/dev/null || die "python3 is required"

mapfile -t state < <(python3 - "$STATE_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)
if document.get("Owner") != "WireguardTCP tests/linux/Provision-LinuxRegression.sh":
    raise SystemExit(f"unexpected provisioning state owner: {document.get('Owner')!r}")
if document.get("Status") != "Ready":
    raise SystemExit(f"provisioning state is not ready: {document.get('Status')!r}")
configuration = document["Configuration"]
guests = configuration["Guests"]
if len(guests) != 2:
    raise SystemExit("provisioning state does not contain exactly two guests")
for guest in guests:
    print(guest["Name"])
private_key = configuration.get("SshPrivateKey")
if not isinstance(private_key, str) or not private_key:
    raise SystemExit("provisioning state does not contain an SSH private key")
print(private_key)
PY
)
(( ${#state[@]} == 3 )) || die "state parser did not return two guests and an SSH private key"
ssh_private_key=${state[2]}
[[ -f $ssh_private_key && -r $ssh_private_key ]] ||
	die "SSH private key is not readable: $ssh_private_key"

guest_ip() {
	local guest=$1 ip
	local -a addresses=()
	mapfile -t addresses < <(
		virsh -c qemu:///system domifaddr "$guest" --source lease 2>/dev/null |
			awk '$3 == "ipv4" {
				split($4, address, "/")
				if (!seen[address[1]]++)
					print address[1]
			}'
	)
	for ip in "${addresses[@]}"; do
		if ssh -o BatchMode=yes -o ConnectTimeout=5 \
			-o StrictHostKeyChecking=yes \
			-o "UserKnownHostsFile=$known_hosts_dir/$guest" \
			-i "$ssh_private_key" "ubuntu@$ip" true >/dev/null 2>&1; then
			printf '%s\n' "$ip"
			return
		fi
	done
	die "could not resolve a reachable libvirt DHCP lease for $guest"
}

known_hosts_dir=$RESULTS_DIR/known-hosts
[[ -d $known_hosts_dir ]] || die "verified known-hosts directory not found: $known_hosts_dir"
for guest in "${state[@]:0:2}"; do
	[[ -f $known_hosts_dir/$guest ]] || die "verified host key not found for $guest"
done

exec python3 "$SCRIPT_DIR/regression.py" \
	--vm-a "${state[0]}" \
	--vm-b "${state[1]}" \
	--vm-a-host "$(guest_ip "${state[0]}")" \
	--vm-b-host "$(guest_ip "${state[1]}")" \
	--ssh-private-key "$ssh_private_key" \
	--known-hosts-dir "$known_hosts_dir" \
	--results-dir "$RESULTS_DIR/runs" \
	"$@"
