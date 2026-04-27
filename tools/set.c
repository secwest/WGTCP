// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

void show_usage(const char *command)
{
	fprintf(stderr, "Usage: %s %s <interface> [listen-port <port>] [fwmark <mark>] [private-key <file path>] [peer <base64 public key> [remove] [preshared-key <file path>] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] [transport tcp/udp]...\n", PROG_NAME, command);
}

int set_main(int argc, const char *argv[])
{
	struct wgdevice *device = NULL;
	int ret = 1;

	DEBUG_PRINT("Entering set_main with argc=%d\n", argc);
	for (int i = 0; i < argc; ++i) {
		DEBUG_PRINT("argv[%d]: %s\n", i, argv[i]);
	}

	if (argc < 3) {
		show_usage(argv[0]);
		DEBUG_PRINT("Exiting set_main with ret=1 (argc < 3)\n");
		return 1;
	}

	device = config_read_cmd(argv + 2, argc - 2);
	if (!device) {
		DEBUG_PRINT("config_read_cmd returned NULL\n");
		goto cleanup;
	}
	DEBUG_PRINT("config_read_cmd succeeded\n");

	strncpy(device->name, argv[1], IFNAMSIZ - 1);
	device->name[IFNAMSIZ - 1] = '\0';
	DEBUG_PRINT("Device name set to %s\n", device->name);

	if (ipc_set_device(device) != 0) {
		perror("Unable to modify interface");
		DEBUG_PRINT("ipc_set_device failed\n");
		goto cleanup;
	}
	DEBUG_PRINT("ipc_set_device succeeded\n");

	ret = 0;

	cleanup:
	free_wgdevice(device);
	if (ret != 0)
		show_usage(argv[0]);
	DEBUG_PRINT("Exiting set_main with ret=%d\n", ret);
	return ret;
}
