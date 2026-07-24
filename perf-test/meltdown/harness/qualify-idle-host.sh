#!/usr/bin/env bash
# Verify a runtime can begin passive TCP activation without inherited carrier state.
set -euo pipefail

if (( EUID != 0 )); then
    echo "qualify-idle-host.sh must run as root" >&2
    exit 2
fi

if (( $# != 2 )); then
    echo "usage: $0 EXPECTED_HOSTNAME EXPECTED_PHYSICAL_IP" >&2
    exit 2
fi

expected_host="$1"
expected_physical_ip="$2"
samples=10
interval_s=0.5
install_dir="${WGTCP_INSTALL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source_dir=/home/azureuser/WireguardTCP-meltdown-2b9513f
module="$source_dir/kernel/wireguard.ko"
tool="$source_dir/tools/wg"
installed_tool="$install_dir/bin/wg"

fail() {
    echo "idle qualification failed: $*" >&2
    exit 1
}

[[ "$(hostname)" == "$expected_host" ]] || fail "hostname mismatch"
[[ "$(uname -r)" == "6.8.0-1062-azure" ]] || fail "kernel mismatch"
ip -brief address | grep -Fq "$expected_physical_ip/" || fail "physical IP missing"
[[ -f "$module" && -x "$tool" && -x "$installed_tool" ]] ||
    fail "runtime artifacts missing"
[[ "$(cat /sys/module/wireguard/srcversion)" == "01DA86291E0FBD2CD3C940C" ]] ||
    fail "module srcversion mismatch"
[[ "$(modinfo -F srcversion "$module")" == "01DA86291E0FBD2CD3C940C" ]] ||
    fail "built module srcversion mismatch"
[[ "$(sha256sum "$module" | awk '{print $1}')" == "771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e" ]] ||
    fail "module hash mismatch"
[[ "$(sha256sum "$tool" | awk '{print $1}')" == "80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3" ]] ||
    fail "tool hash mismatch"
[[ "$(sha256sum "$installed_tool" | awk '{print $1}')" == "80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3" ]] ||
    fail "installed tool hash mismatch"
[[ "$(sha256sum /usr/bin/iperf3 | awk '{print $1}')" == "626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4" ]] ||
    fail "iperf hash mismatch"

for interface in wg-mt-tcp wg-mt-udp; do
    [[ ! -e "/sys/class/net/$interface" ]] || fail "$interface remains present"
done

ip link show type ifb | grep -q . && fail "IFB remains present"
marker="$(find /run/wgtcp-meltdown -maxdepth 1 -type f \
    \( -name '*.active' -o -name '*.restore-failed' \) -print -quit \
    2>/dev/null || true)"
[[ -z "$marker" ]] || fail "campaign marker remains present: $marker"
pgrep -x tcpdump >/dev/null && fail "tcpdump remains active"
pgrep -af '[t]imed-impairment.py' >/dev/null && fail "timed impairment remains active"
systemctl list-units --type=service --state=running --no-legend --plain \
    'wgtcp-sampler-*' 'wgtcp-impairment-*' | grep -q . &&
    fail "transient campaign unit remains active"
pgrep -fa '(apt|dpkg|unattended-upgrade)' >/dev/null &&
    fail "package process remains active"
for lock in /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
    [[ -e "$lock" ]] || continue
    fuser "$lock" >/dev/null 2>&1 && fail "package lock is held: $lock"
done
systemctl --failed --no-legend | grep -q . && fail "failed unit remains"
for unit in \
    wgtcp-meltdown-iperf-inner.service \
    wgtcp-meltdown-iperf-competitor.service \
    wgtcp-meltdown-http.service; do
    systemctl is-active --quiet "$unit" && fail "temporary service remains active: $unit"
done
for unit in apt-daily.timer apt-daily-upgrade.timer apt-daily.service \
    apt-daily-upgrade.service unattended-upgrades.service; do
    [[ "$(systemctl is-active "$unit" 2>&1 || true)" == "inactive" ]] ||
        fail "maintenance unit is active: $unit"
    [[ "$(systemctl is-enabled "$unit" 2>&1 || true)" == "masked-runtime" ]] ||
        fail "maintenance unit is not runtime-masked: $unit"
done

physical_interface="$(ip -o -4 address show |
    awk -v expected="$expected_physical_ip/" '$4 ~ ("^" expected) { print $2; exit }')"
[[ -n "$physical_interface" ]] || fail "could not determine physical interface"
qdisc="$(tc qdisc show dev "$physical_interface")"
grep -Fq 'qdisc mq 0:' <<<"$qdisc" || fail "baseline mq qdisc is absent"
[[ "$(grep -c '^qdisc fq_codel ' <<<"$qdisc")" == "4" ]] ||
    fail "baseline fq_codel qdiscs are absent"
grep -Eq '(netem| htb | tbf | ingress | clsact )' <<<"$qdisc" &&
    fail "impairment qdisc remains"

[[ "$(timedatectl show -p NTPSynchronized --value)" == "yes" ]] ||
    fail "clock is not synchronized"
tracking="$(chronyc tracking)"
leap="$(awk -F: '/Leap status/ { gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2 }' <<<"$tracking")"
system_error="$(awk '/System time/ { print $4 }' <<<"$tracking")"
dispersion="$(awk '/Root dispersion/ { print $4 }' <<<"$tracking")"
[[ "$leap" == "Normal" ]] || fail "clock leap state is not normal"
awk -v s="$system_error" -v d="$dispersion" \
    'BEGIN { exit !((s + 0) <= 0.005 && (d + 0) <= 0.005) }' ||
    fail "clock error exceeds 5 ms"

for (( sample = 1; sample <= samples; sample++ )); do
    established="$(ss -Htn state established \
        '( sport = :51821 or dport = :51821 )' | sed '/^[[:space:]]*$/d' | wc -l)"
    listeners="$(ss -Hltn | awk '$4 ~ /:51821$/ { count++ } END { print count + 0 }')"
    [[ "$established" == "0" ]] ||
        fail "port-51821 established socket at sample $sample: $established"
    [[ "$listeners" == "0" ]] ||
        fail "port-51821 listener at sample $sample: $listeners"
    printf 'idle-sample=%d established=%s listeners=%s\n' \
        "$sample" "$established" "$listeners"
    (( sample == samples )) || sleep "$interval_s"
done

echo "idle qualification passed: ${samples} consecutive carrier-free samples"
