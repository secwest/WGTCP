# WireGuard TCP QuickStart

This guide builds and installs WireguardTCP on two Ubuntu or Debian hosts,
creates a basic point-to-point tunnel, and provides templates for common
advanced layouts.

WireguardTCP keeps WireGuard's keys, Noise encryption, peer identities,
`AllowedIPs`, and administration model. In TCP mode, it places each encrypted
WireGuard message in a small record carried over a long-lived TCP connection.
This can provide connectivity where raw UDP is blocked while preserving a
familiar WireGuard configuration workflow.

## Why use WireguardTCP?

WireguardTCP adds a practical second carrier to WireGuard. The tunnel, keys,
routes, and security model stay familiar; the main configuration change is one
line:

```ini
Transport = tcp
```

This is useful when:

- **UDP is blocked or unreliable.** The tunnel can use an allowed raw TCP port
  instead of depending on UDP reachability.
- **Firewalls and NAT devices favor established TCP flows.** Persistent
  connections and keepalives fit common stateful network policies. The tested
  dual-reachable NAT44 topology passed explicit port forwarding, bidirectional
  traffic, idle keepalives, and recovery after the NAT source port changed.
- **Reliable delivery matters more than minimum latency.** TCP retransmits lost
  outer data, which can preserve inner TCP and UDP payload delivery on some
  lossy paths.
- **You want normal WireGuard administration.** Public/private keys,
  `AllowedIPs`, endpoints, preshared keys, `wg`, `wg-quick`, and systemd service
  management retain their normal roles.
- **You need modern routed configurations.** The regression suite passed IPv4,
  IPv6, dual-stack, full-tunnel policy routing, asymmetric listen ports, live
  route and address changes, `FwMark` reconnects, and `wg-quick` configuration
  reloads.

### Performance advantages seen in testing

TCP mode is not always faster, but it has shown useful strengths in the
repository's measured scenarios:

- On a clean, low-latency x64 test, four-stream bulk TCP reached
  **2789.4 Mbps over TCP-WG versus 2588.2 Mbps over UDP-WG**.
- In selected synthetic-loss tests, outer TCP retransmission preserved much
  more application throughput and inner UDP delivery than the UDP carrier.
- All 82 clean calibration and finite-queue/RTT screening cells in the newer
  physical-carrier campaign were stable. No-loss 16-flow TCP controls at
  200-400 ms delivered about 47 Mbps with essentially no zero-delivery stalls.
- The full two-VM functional campaign passed all runtime tunnel cases,
  including NAT44, IPv4/IPv6, full-tunnel routing, reconnects, keepalives,
  configuration persistence, and forced short-write recovery.

These are measured examples, not a promise that TCP mode will outperform UDP
on every path. High latency, sustained congestion, or severe loss can make an
ordered TCP stream slower through head-of-line blocking. The detailed test
summary is in [`PERFORMANCE.md`](PERFORMANCE.md), with complete conditions and
limitations in
[`perf-test/REPORT.md`](perf-test/REPORT.md) and
[`docs/TCP_MELTDOWN.md`](docs/TCP_MELTDOWN.md).

### The setup in plain language

The complete first-tunnel procedure below is:

1. Install a compiler, matching kernel headers, and WireGuard tools.
2. Run two build commands for the modified `wg` tool and kernel module.
3. Install and load the module on both Linux hosts.
4. Generate ordinary WireGuard keys.
5. Add `Transport = tcp` to two familiar `wg-quick` configuration files.
6. Allow one TCP port, start `wg0`, and verify it with `ping`.

No relay, proxy, userspace tunnel daemon, certificate authority, or new key
format is required. Both endpoints do need this modified Linux module and
modified `wg` tool.

TCP mode is experimental. It is not HTTP or TLS camouflage, both endpoints must
run this implementation, and TCP retransmission can increase latency through
head-of-line blocking. Prefer normal WireGuard UDP when it works and use TCP
only after evaluating the target network and workload.

## Install without compiling on Ubuntu 24.04

Prebuilt archives are available for Ubuntu 24.04 on `amd64` and `arm64`:

- [amd64, kernel 6.8.0-136-generic](docs/downloads/WireguardTCP-ubuntu-24.04-amd64-6.8.0-136-generic.tar.gz)
- [arm64, kernel 6.8.0-136-generic](docs/downloads/WireguardTCP-ubuntu-24.04-arm64-6.8.0-136-generic.tar.gz)
- [archive SHA-256 checksums](docs/downloads/SHA256SUMS.txt)

These archives contain the modified `wg` tool, the production
`wireguard.ko`, and the complete compiled source tree. They are intentionally
strict: the installer accepts only Ubuntu 24.04, the archive's architecture,
and the exact running kernel `6.8.0-136-generic`. Check both hosts before
downloading:

```bash
. /etc/os-release
printf 'Ubuntu %s, architecture %s, kernel %s\n' \
  "$VERSION_ID" "$(dpkg --print-architecture)" "$(uname -r)"
```

If the kernel differs, use the source-build procedure below instead of trying
to force-install the module. Kernel modules are tied to the kernel release and
ABI.

After downloading the archive for the host's architecture, compare its digest
with `docs/downloads/SHA256SUMS.txt`, then extract and install it. This `amd64`
example is identical for `arm64` except for the archive name:

```bash
archive=WireguardTCP-ubuntu-24.04-amd64-6.8.0-136-generic.tar.gz
sha256sum "$archive"
tar -xzf "$archive"
cd "${archive%.tar.gz}"

ip -o link show type wireguard
sudo ./install.sh
```

The interface check must print nothing. Bring down and remove any active
WireGuard interfaces before running the installer. The installer verifies all
payload hashes, installs `wg` under `/usr/local/bin`, installs the module under
`/lib/modules/6.8.0-136-generic/updates/wireguardtcp/`, runs `depmod`, loads
the module, and confirms that the new module was selected.

The module is unsigned. Secure Boot must be disabled or the module must be
signed with a key trusted by the host. Verify the installation:

```bash
command -v wg
wg --version
modinfo -n wireguard
```

`command -v wg` should report `/usr/local/bin/wg`, and `modinfo -n wireguard`
should report the `updates/wireguardtcp/wireguard.ko` path. Continue at
[Generate one key pair per host](#4-generate-one-key-pair-per-host).

## Before you begin

You need:

- two Linux hosts running compatible kernels with loadable WireGuard modules;
- root access and matching kernel headers on both hosts;
- bidirectional TCP reachability between the configured listen ports;
- this repository checked out at the same revision on both hosts; and
- Secure Boot disabled, or a locally signed module trusted by each host.

The examples use these documentation addresses:

| | Host A | Host B |
|---|---|---|
| Underlay address | `198.51.100.10` | `203.0.113.20` |
| Tunnel address | `10.50.0.1/24` | `10.50.0.2/24` |
| TCP listen port | `51820` | `51820` |

Replace the underlay addresses with addresses that the hosts can actually
reach. Do not assign the documentation addresses to production systems.

The module replaces the running stock WireGuard module. Stop or migrate active
WireGuard interfaces before installing it. A kernel upgrade requires a rebuild
for the new `uname -r`.

## 1. Install build prerequisites

Run on both hosts:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential libmnl-dev linux-headers-"$(uname -r)" \
  pkg-config wireguard-tools

test -f "/lib/modules/$(uname -r)/build/Makefile"
modinfo wireguard
```

The active kernel must expose WireGuard as a module rather than compiling it
directly into the kernel:

```bash
grep '^CONFIG_WIREGUARD=' "/boot/config-$(uname -r)"
```

The supported result is `CONFIG_WIREGUARD=m`.

## 2. Build the modified tool and kernel module

From the repository root on both hosts:

```bash
make -C tools clean
make -C tools -j"$(nproc)"

make -C "/lib/modules/$(uname -r)/build" \
  M="$PWD/kernel" CONFIG_WIREGUARD=m clean
make -C "/lib/modules/$(uname -r)/build" \
  M="$PWD/kernel" CONFIG_WIREGUARD=m -j"$(nproc)" modules
```

The outputs are:

- `tools/wg`, the modified configuration tool; and
- `kernel/wireguard.ko`, the modified kernel module.

## 3. Install and load WireguardTCP

Delete every active WireGuard interface before replacing the module:

```bash
ip -o link show type wireguard
```

If that command lists an interface, bring it down with
`wg-quick down <interface>` or remove it before continuing.

Install the tool and module on both hosts:

```bash
sudo make -C tools PREFIX=/usr install

kernel_release=$(uname -r)
sudo install -D -m 0644 kernel/wireguard.ko \
  "/lib/modules/$kernel_release/updates/wireguardtcp/wireguard.ko"
sudo depmod -a "$kernel_release"

if grep -q '^wireguard ' /proc/modules; then
  sudo modprobe -r wireguard
fi
sudo modprobe wireguard
```

Confirm that the loaded module resolves to the installed update and that the
modified tool accepts the transport configuration:

```bash
modinfo -n wireguard
wg --version

sudo ip link add wgtcp-check type wireguard
sudo wg set wgtcp-check transport tcp
sudo wg showconf wgtcp-check | grep -i '^transport = tcp$'
sudo ip link del wgtcp-check
```

`modinfo -n wireguard` should report the
`updates/wireguardtcp/wireguard.ko` path. If `modprobe` reports a key or
signature error, sign the module using the host's trusted Machine Owner Key or
disable Secure Boot according to the operating system's policy.

Installing with `PREFIX=/usr` intentionally replaces the distribution's `wg`
and `wg-quick` commands. A `wireguard-tools` package upgrade may overwrite
them; rebuild and reinstall this repository afterward.

## 4. Generate one key pair per host

Run on both hosts:

```bash
sudo install -d -m 0700 /etc/wireguard
sudo sh -c 'umask 077
  wg genkey > /etc/wireguard/wg0.key
  wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub'
sudo cat /etc/wireguard/wg0.pub
```

Exchange only the `.pub` values. Never copy a private key to the other host or
commit it to source control.

For the configurations below:

- `<HOST_A_PRIVATE_KEY>` is the content of Host A's `wg0.key`;
- `<HOST_A_PUBLIC_KEY>` is the content of Host A's `wg0.pub`; and
- the Host B placeholders refer to Host B's corresponding files.

## 5. Create a basic two-host tunnel

On **Host A**, create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.50.0.1/24
PrivateKey = <HOST_A_PRIVATE_KEY>
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32
Endpoint = 203.0.113.20:51820
PersistentKeepalive = 25
```

On **Host B**, create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.50.0.2/24
PrivateKey = <HOST_B_PRIVATE_KEY>
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32
Endpoint = 198.51.100.10:51820
PersistentKeepalive = 25
```

Protect both files and allow inbound TCP on both hosts:

```bash
sudo chmod 0600 /etc/wireguard/wg0.conf
sudo ufw allow 51820/tcp
```

TCP mode also binds the companion WireGuard UDP socket on the same numeric
port. If the deployment must use TCP exclusively, explicitly block the UDP
port:

```bash
sudo ufw deny 51820/udp
```

Adapt the firewall commands if the host uses nftables, firewalld, or a cloud
security group.

## 6. Start and verify the tunnel

Start Host A and then Host B:

```bash
sudo wg-quick up wg0
```

Check the configuration and TCP sockets:

```bash
sudo wg show wg0
sudo wg showconf wg0
sudo ss -lntp | grep ':51820'
sudo ss -ntp | grep ':51820'
```

From Host A:

```bash
ping -c 4 10.50.0.2
```

From Host B:

```bash
ping -c 4 10.50.0.1
```

After both directions work, enable the tunnel at boot:

```bash
sudo systemctl enable wg-quick@wg0
```

Useful lifecycle commands are:

```bash
sudo wg-quick down wg0
sudo wg-quick up wg0
sudo systemctl restart wg-quick@wg0
sudo journalctl -u wg-quick@wg0
sudo dmesg --ctime | grep -i wireguard
```

Set `Transport` and `ListenPort` while the interface is down. Live transport or
TCP listen-port changes are rejected to avoid replacing sockets beneath active
peers.

## How operation differs from stock WireGuard

The modified `wg` tool sends the selected interface transport to the kernel
through WireGuard's generic-netlink configuration API. `Transport = udp`
retains the normal datagram path. `Transport = tcp` creates a TCP listener and
outbound per-peer connections, frames encrypted WireGuard messages, and passes
authenticated records back into the normal WireGuard receive path.

There is no automatic transport negotiation or fallback. Transport selection
applies to the entire interface, so use separate interfaces when some peers
need UDP and others need TCP. Peer keys and `AllowedIPs` still decide identity
and routing; the outer TCP connection does not replace WireGuard
authentication.

The practical benefit is an explicit TCP carrier for networks where UDP is
unavailable. It retains familiar keys and configuration, supports normal
WireGuard inner IPv4 and IPv6 traffic, and can work with stateful firewalls and
explicit port forwards. The costs are additional connection state, TCP
head-of-line blocking, and less mature roaming and one-sided NAT behavior.

## Advanced configuration templates

### Asymmetric listen ports

Each host may listen on a different TCP port. Host A:

```ini
[Interface]
Address = 10.50.0.1/24
PrivateKey = <HOST_A_PRIVATE_KEY>
ListenPort = 51821
Transport = tcp

[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32
Endpoint = 203.0.113.20:51822
PersistentKeepalive = 25
```

Host B:

```ini
[Interface]
Address = 10.50.0.2/24
PrivateKey = <HOST_B_PRIVATE_KEY>
ListenPort = 51822
Transport = tcp

[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32
Endpoint = 198.51.100.10:51821
PersistentKeepalive = 25
```

Allow Host A's `51821/tcp` and Host B's `51822/tcp` through their firewalls.

### Routed site-to-site tunnel

This template routes `10.10.0.0/24` behind Host A to `10.20.0.0/24` behind
Host B without NAT. Enable forwarding on both gateways:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' | \
  sudo tee /etc/sysctl.d/90-wireguardtcp-forwarding.conf
```

Host A peer section:

```ini
[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32, 10.20.0.0/24
Endpoint = 203.0.113.20:51820
PersistentKeepalive = 25
```

Host B peer section:

```ini
[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32, 10.10.0.0/24
Endpoint = 198.51.100.10:51820
PersistentKeepalive = 25
```

Add routes on each site's LAN router so `10.10.0.0/24` and `10.20.0.0/24`
use the local WireguardTCP gateway. Also permit forwarding between the LAN
interface and `wg0`; do not add masquerading unless overlapping policy or
return-route constraints require it.

### Dual-stack tunnel and IPv6 carrier

Both inner tunnel families can share one interface. An IPv6 outer endpoint is
written in brackets:

```ini
[Interface]
Address = 10.50.0.1/24, fd50::1/64
PrivateKey = <HOST_A_PRIVATE_KEY>
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32, fd50::2/128
Endpoint = [2001:db8:20::2]:51820
PersistentKeepalive = 25
```

Host B uses the mirrored tunnel addresses and Host A's IPv6 endpoint:

```ini
[Interface]
Address = 10.50.0.2/24, fd50::2/64
PrivateKey = <HOST_B_PRIVATE_KEY>
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32, fd50::1/128
Endpoint = [2001:db8:10::1]:51820
PersistentKeepalive = 25
```

Use Host B's real reachable IPv6 address in place of the documentation prefix.
Likewise, replace Host A's documentation prefix in the Host B template.
For a link-local carrier, include its interface scope, for example
`[fe80::2%eth0]:51820`, and verify that both hosts are on the same link.

### Single-private NAT44

TCP mode supports a private peer behind ordinary source NAT without an inbound
port forward. Configure the private peer with the reachable peer's TCP endpoint
and let it initiate the carrier. The reachable peer may omit `Endpoint`; after
the accepted stream carries authenticated WireGuard traffic, it promotes that
exact stream to the configured peer and uses it bidirectionally.

Example:

- Host A listens privately on `10.0.0.10:51821` behind source NAT.
- Host B listens publicly on `203.0.113.20:51822`.

Host A:

```ini
[Interface]
Address = 10.50.0.1/24
PrivateKey = <HOST_A_PRIVATE_KEY>
ListenPort = 51821
Transport = tcp

[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32
Endpoint = 203.0.113.20:51822
PersistentKeepalive = 25
```

Host B:

```ini
[Interface]
Address = 10.50.0.2/24
PrivateKey = <HOST_B_PRIVATE_KEY>
ListenPort = 51822
Transport = tcp

[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32
```

Permit Host A to make the outbound TCP connection and permit Host B's listener
port. No DNAT rule or inbound forward to Host A is required. Keep
`PersistentKeepalive` on the private peer when the NAT mapping must survive
idle periods.

If both peers have configured, reachable endpoints, both may initiate. The
first usable authenticated result is not an operator-visible election:
whichever authenticated carrier the implementation retains carries the tunnel,
and the other connection is retired or becomes irrelevant. Do not build
external policy around a particular connection direction winning.

## Troubleshooting

| Symptom | Check |
|---|---|
| `wg: unrecognized command` or transport parse failure | Confirm `command -v wg` resolves to the installed modified tool; reinstall after distribution package upgrades |
| `Operation not supported` when setting TCP | Confirm the modified module is loaded with `modinfo -n wireguard` and that it was built for the running kernel |
| `Key was rejected by service` from `modprobe` | Sign the module with a trusted key or adjust Secure Boot policy |
| `Device or resource busy` during module removal | Bring down every WireGuard interface before `modprobe -r wireguard` |
| Listener exists but no connection forms | Verify both endpoint addresses, both TCP firewall rules, both configured listen ports, and any NAT forwards |
| Tunnel connects but routed LAN traffic fails | Check `net.ipv4.ip_forward`, forwarding firewall rules, `AllowedIPs`, and return routes |
| Configuration change returns `EBUSY` | Bring the interface down before changing `Transport` or the TCP listen port |

Capture these diagnostics from both endpoints when investigating:

```bash
uname -a
modinfo -n wireguard
sudo wg show
sudo wg showconf wg0
sudo ss -lntp
sudo ss -ntp
ip address show dev wg0
ip route
sudo journalctl -u wg-quick@wg0 --no-pager
sudo dmesg --ctime | tail -n 100
```
