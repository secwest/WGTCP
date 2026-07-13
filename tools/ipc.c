// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "containers.h"
#include "ipc.h"

struct string_list {
	char *buffer;
	size_t len;
	size_t cap;
};

#define DEBUG_PRINT(fmt, args...) do { } while (0)

static int string_list_add(struct string_list *list, const char *str)
{
	DEBUG_PRINT("Entering string_list_add\n");
	
	size_t len = strlen(str) + 1;
	DEBUG_PRINT("string_list_add: Adding string '%s' of length %zu\n", str, len);

	if (len == 1) {
		DEBUG_PRINT("Exiting string_list_add\n");
		return 0;
	}

	if (len >= list->cap - list->len) {
		char *new_buffer;
		size_t new_cap = list->cap * 2;

		DEBUG_PRINT("string_list_add: Current capacity %zu is not enough for new string, resizing...\n", list->cap);

		if (new_cap < list->len + len + 1)
			new_cap = list->len + len + 1;

		DEBUG_PRINT("string_list_add: New capacity will be %zu\n", new_cap);
		new_buffer = realloc(list->buffer, new_cap);
		if (!new_buffer) {
			DEBUG_PRINT("string_list_add: Memory allocation failed: %s\n", strerror(errno));
			DEBUG_PRINT("Exiting string_list_add\n");
			return -errno;
		}
		list->buffer = new_buffer;
		list->cap = new_cap;
	}
	memcpy(list->buffer + list->len, str, len);
	list->len += len;
	list->buffer[list->len] = '\0';

	DEBUG_PRINT("string_list_add: String added. New length is %zu\n", list->len);
	DEBUG_PRINT("Exiting string_list_add\n");
	return 0;
}

#include "ipc-uapi.h"
#if defined(__linux__)
#include "ipc-linux.h"
#elif defined(__OpenBSD__)
#include "ipc-openbsd.h"
#elif defined(__FreeBSD__)
#include "ipc-freebsd.h"
#elif defined(_WIN32)
#include "ipc-windows.h"
#endif

/* first\0second\0third\0forth\0last\0\0 */
char *ipc_list_devices(void)
{
	DEBUG_PRINT("Entering ipc_list_devices\n");

	struct string_list list = { 0 };
	int ret;

	DEBUG_PRINT("ipc_list_devices: Listing devices...\n");

#ifdef IPC_SUPPORTS_KERNEL_INTERFACE
	ret = kernel_get_wireguard_interfaces(&list);
	if (ret < 0) {
		DEBUG_PRINT("ipc_list_devices: Failed to get kernel interfaces: %d\n", ret);
		goto cleanup;
	}
#endif
	ret = userspace_get_wireguard_interfaces(&list);
	if (ret < 0) {
		DEBUG_PRINT("ipc_list_devices: Failed to get userspace interfaces: %d\n", ret);
		goto cleanup;
	}

cleanup:
	errno = -ret;
	if (errno) {
		DEBUG_PRINT("ipc_list_devices: Error occurred: %s\n", strerror(errno));
		free(list.buffer);
		DEBUG_PRINT("Exiting ipc_list_devices\n");
		return NULL;
	}
	DEBUG_PRINT("Exiting ipc_list_devices\n");
	return list.buffer ?: strdup("\0");
}

int ipc_get_device(struct wgdevice **dev, const char *iface)
{
	DEBUG_PRINT("Entering ipc_get_device\n");
	DEBUG_PRINT("ipc_get_device: Getting device for interface '%s'\n", iface);

#ifdef IPC_SUPPORTS_KERNEL_INTERFACE
	if (userspace_has_wireguard_interface(iface)) {
		DEBUG_PRINT("ipc_get_device: Interface '%s' found in userspace\n", iface);
		DEBUG_PRINT("Exiting ipc_get_device\n");
		return userspace_get_device(dev, iface);
	}
	DEBUG_PRINT("ipc_get_device: Interface '%s' found in kernel space\n", iface);
	DEBUG_PRINT("Exiting ipc_get_device\n");
	return kernel_get_device(dev, iface);
#else
	DEBUG_PRINT("Exiting ipc_get_device\n");
	return userspace_get_device(dev, iface);
#endif
}

int ipc_set_device(struct wgdevice *dev)
{
	DEBUG_PRINT("Entering ipc_set_device\n");
	DEBUG_PRINT("ipc_set_device: Setting device '%s'\n", dev->name);

#if !defined(__linux__)
	if (dev->flags & WGDEVICE_HAS_TRANSPORT) {
		if (dev->transport == WG_TRANSPORT_TCP) {
			errno = EOPNOTSUPP;
			return -EOPNOTSUPP;
		}
		dev->flags &= ~WGDEVICE_HAS_TRANSPORT;
	}
#endif

#ifdef IPC_SUPPORTS_KERNEL_INTERFACE
	if (userspace_has_wireguard_interface(dev->name)) {
		if (dev->flags & WGDEVICE_HAS_TRANSPORT) {
			if (dev->transport == WG_TRANSPORT_TCP) {
				errno = EOPNOTSUPP;
				return -EOPNOTSUPP;
			}
			dev->flags &= ~WGDEVICE_HAS_TRANSPORT;
		}
		DEBUG_PRINT("ipc_set_device: Interface '%s' found in userspace\n", dev->name);
		DEBUG_PRINT("Exiting ipc_set_device\n");
		return userspace_set_device(dev);
	}
	DEBUG_PRINT("ipc_set_device: Interface '%s' found in kernel space\n", dev->name);
	DEBUG_PRINT("Exiting ipc_set_device\n");
	return kernel_set_device(dev);
#else
	if (dev->flags & WGDEVICE_HAS_TRANSPORT) {
		if (dev->transport == WG_TRANSPORT_TCP) {
			errno = EOPNOTSUPP;
			return -EOPNOTSUPP;
		}
		dev->flags &= ~WGDEVICE_HAS_TRANSPORT;
	}
	DEBUG_PRINT("Exiting ipc_set_device\n");
	return userspace_set_device(dev);
#endif
}
