# WireguardTCP

WireguardTCP adds an opt-in TCP transport to the Linux WireGuard kernel module.
It keeps WireGuard's keys, Noise encryption, peer identities, `AllowedIPs`,
rekeying, and administration model while carrying encrypted WireGuard messages
over a persistent TCP connection.

UDP remains the default. Choose TCP when UDP is blocked or when an established
TCP flow works better with the network between your peers.

- [Install and configure your first tunnel](QUICKSTART.md)
- [Review measured performance](PERFORMANCE.md)
- [Read the transport design and security model](docs/TCP_TRANSPORT_DESIGN.md)
- [See releases](https://github.com/secwest/WireguardTCP/releases)

## Why use it?

| Benefit | What it means operationally |
|---|---|
| Works without UDP | Carry a WireGuard tunnel across networks that permit raw TCP but block UDP |
| Familiar WireGuard configuration | Keep the usual keys, peers, `AllowedIPs`, preshared keys, keepalives, `wg`, and `wg-quick` workflow |
| No proxy or relay | Packet flow stays in the kernel; ordinary operation needs no additional tunnel daemon or userspace encapsulation hop |
| Outbound-only NAT traversal | A private peer can initiate through ordinary SNAT without an inbound port forward; the reachable peer promotes the authenticated connection |
| Roaming and recovery | Authenticated source-address and source-port changes, route changes, uplink changes, socket-mark changes, and failed carriers can establish a replacement connection |
| IPv4 and IPv6 | TCP listeners and tunnels support IPv4, IPv6, dual-stack, and scoped link-local IPv6 configurations |
| Per-interface choice | Run TCP and UDP WireGuard interfaces side by side for different routes or fallback policies |

WireguardTCP is not HTTP or TLS camouflage. Both ends of a TCP tunnel need the
modified Linux module and `wg` tool, and TCP is selected for the entire
WireGuard interface rather than negotiated per peer.

## Design summary

WireGuard encryption remains authoritative. TCP framing only preserves message
boundaries while the encrypted WireGuard packets travel through a byte stream.

```text
inner IP -> WireGuard encrypt -> UDP socket             (Transport = udp)
                              -> frame -> TCP connection (Transport = tcp)

TCP connection -> frame parser -> WireGuard authenticate/decrypt -> inner IP
```

TCP mode uses a persistent carrier for each active peer. An accepted connection
starts without a peer identity; after it carries an authenticated WireGuard
handshake, it can become that peer's active carrier. This is what allows a
private peer to dial outward through NAT without requiring a reverse connection.

When both peers are directly reachable, either authenticated connection may be
retained. Older or duplicate connections cannot displace the current carrier.

## Performance

TCP mode performed competitively on clean paths and delivered major gains in
several lossy-path tests. Its reliable outer carrier can preserve application
traffic that would otherwise be exposed directly to packet loss.

Selected measured results from the repository's application campaign:

| Workload | TCP-WG | UDP-WG | Result |
|---|---:|---:|---:|
| Bulk TCP, x64, clean 56 ms path | 519.3 Mb/s | 428.9 Mb/s | TCP-WG +21.1% |
| Sequential HTTPS, x64, clean LAN | 152.55 req/s | 131.14 req/s | TCP-WG +16.3% |
| Bulk TCP, ARM64, clean LAN | 2918.4 Mb/s | 2777.2 Mb/s | TCP-WG +5.1% |

In selected synthetic-loss tests, the TCP carrier delivered substantially more
inner TCP and UDP traffic because the outer stream retransmitted lost data.

A separate physical-carrier campaign recorded **zero formal TCP-over-TCP
meltdowns across 122 valid post-repair executions**. The detailed report also
documents the deliberately extreme loss, latency, queue, and concurrency
conditions used to explore the transport's operating envelope.

See [PERFORMANCE.md](PERFORMANCE.md) for the practical summary and
[the performance report](perf-test/REPORT.md) for the complete matrices.

### Where TCP fits

| Situation | Recommended starting point |
|---|---|
| Existing WireGuard UDP already meets the deployment's needs | Keep the default UDP transport |
| UDP is blocked but raw TCP is reachable | Select WireguardTCP |
| A private peer cannot receive inbound connections | Use outbound-only TCP with a persistent keepalive |
| Reliable application delivery matters on a lossy path | Compare TCP and UDP results on that path |
| You want an operational fallback | Use separate TCP and UDP WireGuard interfaces |

## Install

The complete [QuickStart](QUICKSTART.md) covers prerequisites, source builds,
module installation, key generation, firewalls, systemd operation, NAT, IPv6,
full-tunnel routing, and troubleshooting.

### Ubuntu 24.04 binaries

Prebuilt archives are available for Ubuntu 24.04 running the exact
`6.8.0-136-generic` kernel:

- [amd64 archive](docs/downloads/WireguardTCP-ubuntu-24.04-amd64-6.8.0-136-generic.tar.gz)
- [arm64 archive](docs/downloads/WireguardTCP-ubuntu-24.04-arm64-6.8.0-136-generic.tar.gz)
- [SHA-256 checksums](docs/downloads/SHA256SUMS.txt)

The guarded installer verifies the Ubuntu release, architecture, kernel ABI,
and payload checksums before installing the modified `wg` tool and module. If
your running kernel differs, build from source instead. See the
[binary installation instructions](QUICKSTART.md#install-without-compiling-on-ubuntu-2404)
for the extraction, Secure Boot, and verification steps.

### Build from source

For a source build, both Linux endpoints need matching kernel headers, a
loadable WireGuard module, build tools, and `libmnl`. From the repository root:

```bash
make -C tools -j"$(nproc)"
make -C "/lib/modules/$(uname -r)/build" \
  M="$PWD/kernel" CONFIG_WIREGUARD=m -j"$(nproc)" modules
```

This produces the modified `wg` tool at `tools/wg` and the kernel module at
`kernel/wireguard.ko`. Installing a kernel module is kernel- and
distribution-specific; follow the QuickStart rather than replacing an active
WireGuard module blindly. Rebuild the module after a kernel upgrade.

Ubuntu 24.04 release archives can be built with:

```bash
./scripts/build-ubuntu-binary.sh
```

The resulting architecture- and kernel-specific archive includes checksums,
the modified tool, the module, a manifest, and a guarded installer. Verify that
its Ubuntu release, architecture, kernel ABI, and SHA-256 values match the
target before running `sudo ./install.sh` from the extracted archive.

## Configure a tunnel

TCP configuration uses the ordinary `wg-quick` format with one additional
interface setting:

```ini
Transport = tcp
```

### Two reachable peers

Host A, `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <HOST_A_PRIVATE_KEY>
Address = 10.50.0.1/24
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_B_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32
Endpoint = host-b.example.net:51820
PersistentKeepalive = 25
```

Host B:

```ini
[Interface]
PrivateKey = <HOST_B_PRIVATE_KEY>
Address = 10.50.0.2/24
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <HOST_A_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32
Endpoint = host-a.example.net:51820
PersistentKeepalive = 25
```

Allow inbound TCP port `51820` on each reachable host, then start and verify the
tunnel:

```bash
sudo wg-quick up wg0
sudo wg show wg0
ping -c 3 10.50.0.2    # from Host A
```

The same setting can be applied directly while the interface is down:

```bash
sudo wg set wg0 listen-port 51820 transport tcp
```

### Private peer behind one NAT

Only the private peer needs an `Endpoint`. Its outbound connection is
authenticated and adopted by the reachable peer, so the private side needs no
DNAT rule or forwarded listen port.

Reachable peer:

```ini
[Interface]
PrivateKey = <PUBLIC_HOST_PRIVATE_KEY>
Address = 10.50.0.1/24
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <PRIVATE_HOST_PUBLIC_KEY>
AllowedIPs = 10.50.0.2/32
```

Private peer:

```ini
[Interface]
PrivateKey = <PRIVATE_HOST_PRIVATE_KEY>
Address = 10.50.0.2/24
ListenPort = 51820
Transport = tcp

[Peer]
PublicKey = <PUBLIC_HOST_PUBLIC_KEY>
AllowedIPs = 10.50.0.1/32
Endpoint = public.example.net:51820
PersistentKeepalive = 25
```

Allow TCP `51820` on the reachable peer. Choose a keepalive interval shorter
than the NAT's idle timeout. If the private peer's public address or source port
changes, authenticated traffic can promote the replacement carrier and retire
the old one.

## Operational notes

- UDP remains the default when `Transport` is omitted on a new interface.
- `Transport = tcp` requires this implementation at both endpoints. It does not
  interoperate on that interface with a stock UDP-only WireGuard peer.
- Transport mode is interface-wide. Use separate interfaces for TCP and UDP
  peers.
- Change transport mode or the TCP listen port while the interface is down.
- An omitted or zero `ListenPort` chooses a random port when the interface
  starts. Configure the remote endpoint with the selected port.
- TCP mode also binds WireGuard's companion UDP socket to the same numeric
  listen port. Block UDP at the firewall when the deployment must be TCP-only.
- `wg showconf`, `setconf`, `syncconf`, and `wg-quick` SaveConfig preserve
  `Transport = tcp`.
- The current implementation is provided through the Linux kernel and generic
  netlink backend; do not assume wireguard-go or non-Linux support.
- TCP framing adds no new encryption. WireGuard's authenticated Noise protocol
  continues to determine peer identity and packet validity.

## Repository layout

```text
kernel/                       Linux WireGuard module with TCP transport
tools/                        Modified wg and wg-quick tools
include/uapi/                 Additive Linux transport UAPI
scripts/                      Ubuntu binary packaging and installation scripts
QUICKSTART.md                 Complete installation and configuration guide
PERFORMANCE.md                Performance summary and measured results
docs/TCP_TRANSPORT_DESIGN.md  Architecture, security, parity, and validation
tests/                        Source, namespace, Linux VM, and Hyper-V tests
perf-test/                    Performance harnesses, reports, and evidence
```

## More documentation

- [QuickStart](QUICKSTART.md)
- [Performance summary](PERFORMANCE.md)
- [TCP transport design](docs/TCP_TRANSPORT_DESIGN.md)
- [TCP-over-TCP methodology and evidence](docs/TCP_MELTDOWN.md)
- [Change log](CHANGELOG.md)
- [Design log](DESIGNLOG.md)
- [Linux regression lab](tests/linux/README.md)
- [Hyper-V regression lab](tests/hyperv/README.md)
