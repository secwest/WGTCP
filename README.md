# WireguardTCP

**WireGuard's security and simplicity, with a TCP carrier that reaches networks
where UDP cannot.**

WireguardTCP adds a high-performance TCP transport to the Linux WireGuard
kernel module. It keeps the keys, Noise encryption, peer identities,
`AllowedIPs`, rekeying, and administration model you already know while carrying
encrypted WireGuard messages over persistent TCP connections. Two years of
performance tuning and reliability engineering have shaped the transport from
its framing and connection lifecycle through NAT roaming and failure recovery.

- **[Install and configure your first tunnel](QUICKSTART.md)**
- [Download Ubuntu 24.04 binaries](#ubuntu-2404-binaries)
- [Review measured performance](PERFORMANCE.md)
- [Build from source](#build-from-source)

## Why use it?

| Benefit | What it means operationally |
|---|---|
| Reach more networks | Establish WireGuard tunnels across networks that permit TCP while restricting UDP |
| Start quickly | Use ready-to-install Ubuntu 24.04 archives for both amd64 and arm64 |
| Familiar WireGuard configuration | Keep the usual keys, peers, `AllowedIPs`, preshared keys, keepalives, `wg`, and `wg-quick` workflow |
| Kernel-native operation | Carry packets without a proxy, relay, extra tunnel daemon, or userspace encapsulation hop |
| Simple NAT deployment | Let a private peer initiate through ordinary SNAT without adding an inbound port forward |
| Seamless roaming and recovery | Promote authenticated replacement connections after address, port, route, uplink, socket-mark, or carrier changes |
| Strong measured performance | Match or exceed UDP-WG in several clean-path workloads and preserve substantially more traffic in selected lossy-path tests |
| Lower CPU utilization | Use 6.7–10.9% less mean CPU for clean-LAN bulk transfer and 11.7–16.6% less for clean-LAN sequential HTTPS in the measured x64 and ARM64 cells |
| IPv4 and IPv6 | Use IPv4, IPv6, dual-stack, and scoped link-local IPv6 configurations |

## Two years of tuning and validation

WireguardTCP has been developed as a complete kernel transport rather than a
thin TCP wrapper. Iterative profiling and fault testing improved writer
wakeups, short-write continuation, bounded queues, parser recovery, connection
replacement, authenticated promotion, roaming, and exact terminal-I/O cleanup.

The resulting evidence spans both performance and reliability:

| Validation area | Coverage |
|---|---|
| Application performance | 512 unique TCP-WG and UDP-WG comparison cells across x64 and ARM64, four latency tiers, multiple workloads, and a 0–20% configured-loss range |
| Physical-carrier behavior | 122 valid post-repair executions examining latency, queues, concurrency, recovery, and TCP-over-TCP behavior |
| Automated source and contract suite | 221 tests plus 16 parameterized subtests covering transport, lifecycle, NAT, roaming, namespaces, tooling, packaging, and compatibility |
| End-to-end Linux validation | 40 complete VM scenarios covering UDP/TCP, stock/fork combinations, IPv4/IPv6, policy routing, NAT, roaming, configuration persistence, recovery, and destructive stream faults |
| Platform breadth | Application campaigns cover x64 and ARM64; production, diagnostic, and isolated fault builds have been exercised on Ubuntu 24.04 Linux VMs |

This work is reflected in the current module: its performance characteristics
are measured, its critical stream and socket paths are bounded, and its NAT,
roaming, recovery, and configuration behavior have dedicated end-to-end
coverage.

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
| Mean CPU, ARM64 sequential HTTPS, clean LAN | 51.2% | 61.3% | TCP-WG 16.6% lower |

In selected synthetic-loss tests, the TCP carrier delivered substantially more
inner TCP and UDP traffic because the outer stream retransmitted lost data.
On the clean LAN cells, TCP-WG also reduced mean CPU utilization across both
architectures for bulk transfer and sequential HTTPS.

A separate physical-carrier campaign recorded **zero formal TCP-over-TCP
meltdowns across 122 valid post-repair executions**. The detailed report also
documents the deliberately extreme loss, latency, queue, and concurrency
conditions used to explore the transport's operating envelope.

See [PERFORMANCE.md](PERFORMANCE.md) for the practical summary and
[the performance report](perf-test/REPORT.md) for the complete matrices.

### Great fits for WireguardTCP

| Situation | Recommended starting point |
|---|---|
| Restrictive firewall or network | Carry WireGuard over an allowed TCP port |
| Private site, home, branch, or mobile peer | Dial outward through NAT and keep the mapping active |
| Changing address, source port, route, or uplink | Let authenticated roaming establish the replacement carrier |
| Lossy path where complete delivery matters | Put WireGuard packets on TCP's reliable outer carrier |
| Existing WireGuard operations | Keep using familiar keys, configurations, tools, and service management |
| Multi-path or fallback deployment | Run separate TCP and UDP WireGuard interfaces |

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
`kernel/wireguard.ko`. The QuickStart provides the safe module replacement and
verification steps for your distribution. Rebuild the module after a kernel
upgrade.

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
- The current implementation targets the Linux kernel and generic netlink
  backend.
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
