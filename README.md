# WireGuard TCP Transport

This repository contains the WireGuard TCP transport source extracted from the `tcp` branch of `github.com/jnathan/naked_gun`, cleaned into a standalone layout without the redundant full Linux kernel source tree.

Source snapshot: `jnathan/naked_gun@4211b00ef437`.

## Repository structure

```text
kernel/          WireGuard kernel module source with TCP transport support
tools/           Modified WireGuard userland tools
include/uapi/    Modified WireGuard UAPI header with transport support
docs/            Test relay and tunnel setup notes from the source branch
```

## Building

### Kernel module

```bash
cd kernel
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

Optional diagnostic builds:

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules EXTRA_CFLAGS='-DWG_TCP_DIAG'
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules EXTRA_CFLAGS='-DWG_TCP_VERBOSE'
```

### Userland tools

```bash
cd tools
make
```

The modified `wg` utility supports configuring the WireGuard transport mode through the added UAPI transport attribute.
