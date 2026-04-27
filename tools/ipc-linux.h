// SPDX-License-Identifier: MIT
/*
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define RUNSTATEDIR "/var/run" // Define RUNSTATEDIR here
#define SOCK_PATH RUNSTATEDIR "/wireguard/"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <netinet/in.h>
#include "containers.h"
#include "encoding.h"
#include "netlink.h"

#include <ctype.h>

#define IPC_SUPPORTS_KERNEL_INTERFACE

#define SOCKET_BUFFER_SIZE (mnl_ideal_socket_buffer_size())

struct interface {
	const char *name;
	bool is_wireguard;
};


// Hex dump function for raw data
static void hex_dump(const void *data, size_t size)
{
    const unsigned char *byte = (const unsigned char *)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%06zx: ", i);
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", byte[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%c", isprint(byte[i + j]) ? byte[i + j] : '.');
            else
                printf(" ");
        }
        printf("|\n");
    }
}

// Routine to parse and print flags with verbose values
static void print_flags_verbose(uint32_t flags)
{
    printf("Flags: 0x%08x (", flags);
    if (flags & NLM_F_REQUEST) printf("REQUEST ");
    if (flags & NLM_F_MULTI) printf("MULTI ");
    if (flags & NLM_F_ACK) printf("ACK ");
    if (flags & NLM_F_ECHO) printf("ECHO ");
    if (flags & NLM_F_REPLACE) printf("REPLACE ");
    if (flags & NLM_F_EXCL) printf("EXCL ");
    if (flags & NLM_F_CREATE) printf("CREATE ");
    if (flags & NLM_F_APPEND) printf("APPEND ");
    printf(")\n");
}

// Routine to parse and print peer flags with verbose labels
static void print_peer_flags_verbose(uint32_t flags)
{
    printf("Peer Flags: 0x%08x (", flags);
    if (flags & WGPEER_F_REMOVE_ME) printf("REMOVE_ME ");
    if (flags & WGPEER_F_REPLACE_ALLOWEDIPS) printf("REPLACE_ALLOWEDIPS ");
    if (flags & WGPEER_F_UPDATE_ONLY) printf("UPDATE_ONLY ");
    printf(")\n");
}

// Functions to print the allowed IP attributes
static void print_allowedip_attr(const struct nlattr *attr)
{
    int type = mnl_attr_get_type(attr);

    switch (type) {
    case WGALLOWEDIP_A_FAMILY:
        printf("WGALLOWEDIP_A_FAMILY: %u\n", mnl_attr_get_u16(attr));
        break;
    case WGALLOWEDIP_A_IPADDR:
        printf("WGALLOWEDIP_A_IPADDR: %pIS\n", mnl_attr_get_payload(attr));
        break;
    case WGALLOWEDIP_A_CIDR_MASK:
        printf("WGALLOWEDIP_A_CIDR_MASK: %u\n", mnl_attr_get_u8(attr));
        break;
    default:
        printf("Unknown Allowed IP Attribute Type: %d\n", type);
        break;
    }
}

static void print_peer_allowedips(const struct nlattr *attr)
{
    struct nlattr *nested_attr;
    mnl_attr_for_each_nested(nested_attr, attr) {
        print_allowedip_attr(nested_attr);
    }
}

// Functions to print the peer attributes
static void print_peer_attr(const struct nlattr *attr)
{
    int type = mnl_attr_get_type(attr);

    switch (type) {
    case WGPEER_A_PUBLIC_KEY:
        printf("WGPEER_A_PUBLIC_KEY: %*phN\n", mnl_attr_get_payload_len(attr), mnl_attr_get_payload(attr));
        break;
    case WGPEER_A_PRESHARED_KEY:
        printf("WGPEER_A_PRESHARED_KEY: %*phN\n", mnl_attr_get_payload_len(attr), mnl_attr_get_payload(attr));
        break;
    case WGPEER_A_FLAGS:
        printf("WGPEER_A_FLAGS: %u\n", mnl_attr_get_u32(attr));
        print_peer_flags_verbose(mnl_attr_get_u32(attr));
        break;
    case WGPEER_A_ENDPOINT:
        printf("WGPEER_A_ENDPOINT: %pIS\n", mnl_attr_get_payload(attr));
        break;
    case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
        printf("WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: %u\n", mnl_attr_get_u16(attr));
        break;
    case WGPEER_A_LAST_HANDSHAKE_TIME:
        printf("WGPEER_A_LAST_HANDSHAKE_TIME: %lld.%.9ld\n",
               (long long)((struct timespec *)mnl_attr_get_payload(attr))->tv_sec,
               (long)((struct timespec *)mnl_attr_get_payload(attr))->tv_nsec);
        break;
    case WGPEER_A_RX_BYTES:
        printf("WGPEER_A_RX_BYTES: %lu\n", (unsigned long)mnl_attr_get_u64(attr));
        break;
    case WGPEER_A_TX_BYTES:
        printf("WGPEER_A_TX_BYTES: %lu\n", (unsigned long)mnl_attr_get_u64(attr));
        break;
    case WGPEER_A_ALLOWEDIPS:
        printf("WGPEER_A_ALLOWEDIPS (Nested Attributes):\n");
        print_peer_allowedips(attr);
        break;
    default:
        printf("Unknown Peer Attribute Type: %d\n", type);
        break;
    }
}

// Functions to print the device attributes
static void print_device_peers(const struct nlattr *attr)
{
    struct nlattr *nested_attr;
    mnl_attr_for_each_nested(nested_attr, attr) {
        print_peer_attr(nested_attr);
    }
}

static void print_device_attr(const struct nlattr *attr)
{
    int type = mnl_attr_get_type(attr);

    switch (type) {
    case WGDEVICE_A_IFINDEX:
        printf("WGDEVICE_A_IFINDEX: %u\n", mnl_attr_get_u32(attr));
        break;
    case WGDEVICE_A_IFNAME:
        printf("WGDEVICE_A_IFNAME: %s\n", mnl_attr_get_str(attr));
        break;
    case WGDEVICE_A_PRIVATE_KEY:
        printf("WGDEVICE_A_PRIVATE_KEY: %*phN\n", mnl_attr_get_payload_len(attr), mnl_attr_get_payload(attr));
        break;
    case WGDEVICE_A_PUBLIC_KEY:
        printf("WGDEVICE_A_PUBLIC_KEY: %*phN\n", mnl_attr_get_payload_len(attr), mnl_attr_get_payload(attr));
        break;
    case WGDEVICE_A_FLAGS:
        printf("WGDEVICE_A_FLAGS: %u\n", mnl_attr_get_u32(attr));
        break;
    case WGDEVICE_A_LISTEN_PORT:
        printf("WGDEVICE_A_LISTEN_PORT: %u\n", mnl_attr_get_u16(attr));
        break;
    case WGDEVICE_A_FWMARK:
        printf("WGDEVICE_A_FWMARK: %u\n", mnl_attr_get_u32(attr));
        break;
    case WGDEVICE_A_PEERS:
        printf("WGDEVICE_A_PEERS (Nested Attributes):\n");
        print_device_peers(attr);
        break;
    case WGDEVICE_A_TRANSPORT:
        printf("WGDEVICE_A_TRANSPORT: %u\n", mnl_attr_get_u8(attr));
        break;
    default:
        printf("Unknown Device Attribute Type: %d\n", type);
        break;
    }
}

static void print_netlink_message_verbose(const struct nlmsghdr *nlh)
{
    struct nlattr *attr;
    int rem = 0;

    printf("Verbose Netlink Message:\n");
    printf("  nlmsg_len: %u\n", nlh->nlmsg_len);
    printf("  nlmsg_type: %u\n", nlh->nlmsg_type);
    
    // Print command
    switch (nlh->nlmsg_type) {
    case WG_CMD_GET_DEVICE:
        printf("  Command: WG_CMD_GET_DEVICE\n");
        break;
    case WG_CMD_SET_DEVICE:
        printf("  Command: WG_CMD_SET_DEVICE\n");
        break;
    default:
        printf("  Unknown Command: %u\n", nlh->nlmsg_type);
        break;
    }

    print_flags_verbose(nlh->nlmsg_flags);
    printf("  nlmsg_seq: %u\n", nlh->nlmsg_seq);
    printf("  nlmsg_pid: %u\n", nlh->nlmsg_pid);
    printf("Attributes:\n");

    mnl_attr_for_each(attr, nlh, rem) {
        switch (nlh->nlmsg_type) {
        case WG_CMD_GET_DEVICE:
        case WG_CMD_SET_DEVICE:
            print_device_attr(attr);
            break;
        default:
            printf("Unknown Netlink Message Type: %u\n", nlh->nlmsg_type);
            break;
        }
    }

    printf("Hex Dump of Netlink Message:\n");
    hex_dump(nlh, nlh->nlmsg_len);
}

// Function to print the libmnl formatted netlink message header
static void print_netlink_header_libmnl(const struct nlmsghdr *nlh)
{
    printf("----------------\t------------------\n");
    printf("|  %.010u  |\t| message length |\n", nlh->nlmsg_len);
    printf("| %.05u | %c%c%c%c |\t|  type | flags  |\n",
        nlh->nlmsg_type,
        nlh->nlmsg_flags & NLM_F_REQUEST ? 'R' : '-',
        nlh->nlmsg_flags & NLM_F_MULTI ? 'M' : '-',
        nlh->nlmsg_flags & NLM_F_ACK ? 'A' : '-',
        nlh->nlmsg_flags & NLM_F_ECHO ? 'E' : '-');
    printf("|  %.010u  |\t| sequence number|\n", nlh->nlmsg_seq);
    printf("|  %.010u  |\t|     port ID    |\n", nlh->nlmsg_pid);
    printf("----------------\t------------------\n");
}

// Function to print the libmnl formatted netlink message payload
static void print_netlink_payload_libmnl(const struct nlmsghdr *nlh, size_t extra_header_size)
{
    unsigned int i;
    int rem = 0;

    for (i = sizeof(struct nlmsghdr); i < nlh->nlmsg_len; i += 4) {
        char *b = (char *)nlh;
        struct nlattr *attr = (struct nlattr *)(b + i);

        if (nlh->nlmsg_type < NLMSG_MIN_TYPE) {
            printf("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            printf("|                |\n");
        } else if (extra_header_size > 0) {
            extra_header_size -= 4;
            printf("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            printf("|  extra header  |\n");
        } else if (rem == 0 && (attr->nla_type & NLA_TYPE_MASK) != 0) {
            printf("|%.5u|%c%c|%.5u|\t",
                   attr->nla_len,
                   attr->nla_type & NLA_F_NESTED ? 'N' : '-',
                   attr->nla_type & NLA_F_NET_BYTEORDER ? 'B' : '-',
                   attr->nla_type & NLA_TYPE_MASK);
            printf("|len |flags| type|\n");

            if (!(attr->nla_type & NLA_F_NESTED)) {
                rem = NLA_ALIGN(attr->nla_len) -
                      sizeof(struct nlattr);
            }
        } else if (rem > 0) {
            rem -= 4;
            printf("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            printf("|      data      |");
            printf("\t %c %c %c %c\n",
                   isprint(b[i]) ? b[i] : ' ',
                   isprint(b[i + 1]) ? b[i + 1] : ' ',
                   isprint(b[i + 2]) ? b[i + 2] : ' ',
                   isprint(b[i + 3]) ? b[i + 3] : ' ');
        }
    }
    printf("----------------\t------------------\n");
}

// Print the netlink message using libmnl format
static void print_netlink_message_libmnl(const struct nlmsghdr *nlh)
{
    print_netlink_header_libmnl(nlh);
    print_netlink_payload_libmnl(nlh, 0);
}

// Add a function to print the entire buffer of netlink messages
static void print_netlink_buffer(const void *buf, size_t len)
{
    const struct nlmsghdr *nlh = buf;

    while (mnl_nlmsg_ok(nlh, len)) {
        print_netlink_message_verbose(nlh);
        print_netlink_message_libmnl(nlh);
        nlh = mnl_nlmsg_next(nlh, (int *)&len);
    }
}
static int parse_linkinfo(const struct nlattr *attr, void *data)
{
	struct interface *interface = data;

	print_device_attr(attr);
	if (mnl_attr_get_type(attr) == IFLA_INFO_KIND && !strcmp(WG_GENL_NAME, mnl_attr_get_str(attr)))
		interface->is_wireguard = true;
	return MNL_CB_OK;
}

static int parse_infomsg(const struct nlattr *attr, void *data)
{
	struct interface *interface = data;

	print_device_attr(attr);
	if (mnl_attr_get_type(attr) == IFLA_LINKINFO)
		return mnl_attr_parse_nested(attr, parse_linkinfo, data);
	else if (mnl_attr_get_type(attr) == IFLA_IFNAME)
		interface->name = mnl_attr_get_str(attr);
	return MNL_CB_OK;
}

static int read_devices_cb(const struct nlmsghdr *nlh, void *data)
{
	struct string_list *list = data;
	struct interface interface = { 0 };
	int ret;

	printf("Entering read_devices_cb\n");
	ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), parse_infomsg, &interface);
	if (ret != MNL_CB_OK)
		return ret;
	if (interface.name && interface.is_wireguard)
		ret = string_list_add(list, interface.name);
	if (ret < 0)
		return ret;
	if (nlh->nlmsg_type != NLMSG_DONE)
		return MNL_CB_OK + 1;
	printf("Exiting read_devices_cb\n");
	return MNL_CB_OK;
}

static int kernel_get_wireguard_interfaces(struct string_list *list)
{
	struct mnl_socket *nl = NULL;
	char *rtnl_buffer = NULL;
	size_t message_len;
	unsigned int portid, seq;
	ssize_t len;
	int ret = 0;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;

	printf("Entering kernel_get_wireguard_interfaces\n");
	ret = -ENOMEM;
	rtnl_buffer = calloc(SOCKET_BUFFER_SIZE, 1);
	if (!rtnl_buffer)
		goto cleanup;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		ret = -errno;
		goto cleanup;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ret = -errno;
		goto cleanup;
	}

	seq = time(NULL);
	portid = mnl_socket_get_portid(nl);
	nlh = mnl_nlmsg_put_header(rtnl_buffer);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	message_len = nlh->nlmsg_len;

	if (mnl_socket_sendto(nl, rtnl_buffer, message_len) < 0) {
		ret = -errno;
		goto cleanup;
	}

another:
	if ((len = mnl_socket_recvfrom(nl, rtnl_buffer, SOCKET_BUFFER_SIZE)) < 0) {
		ret = -errno;
		goto cleanup;
	}
	if ((len = mnl_cb_run(rtnl_buffer, len, seq, portid, read_devices_cb, list)) < 0) {
		/* Netlink returns NLM_F_DUMP_INTR if the set of all tunnels changed
		 * during the dump. That's unfortunate, but is pretty common on busy
		 * systems that are adding and removing tunnels all the time. Rather
		 * than retrying, potentially indefinitely, we just work with the
		 * partial results. */
		if (errno != EINTR) {
			ret = -errno;
			goto cleanup;
		}
	}
	if (len == MNL_CB_OK + 1)
		goto another;
	ret = 0;

cleanup:
	free(rtnl_buffer);
	if (nl)
		mnl_socket_close(nl);
	printf("Exiting kernel_get_wireguard_interfaces\n");
	return ret;
}

static int kernel_set_device(struct wgdevice *dev)
{
	int ret = 0;
	struct wgpeer *peer = NULL;
	struct wgallowedip *allowedip = NULL;
	struct nlattr *peers_nest, *peer_nest, *allowedips_nest, *allowedip_nest;
	struct nlmsghdr *nlh;
	struct mnlg_socket *nlg;

	printf("Entering kernel_set_device\n");
	nlg = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
	if (!nlg)
		return -errno;

again:
	nlh = mnlg_msg_prepare(nlg, WG_CMD_SET_DEVICE, NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, dev->name);

	if (!peer) {
		uint32_t flags = 0;

		if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY)
			mnl_attr_put(nlh, WGDEVICE_A_PRIVATE_KEY, sizeof(dev->private_key), dev->private_key);
		if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
			mnl_attr_put_u16(nlh, WGDEVICE_A_LISTEN_PORT, dev->listen_port);
		if (dev->flags & WGDEVICE_HAS_FWMARK)
			mnl_attr_put_u32(nlh, WGDEVICE_A_FWMARK, dev->fwmark);
		if (dev->flags & WGDEVICE_REPLACE_PEERS)
			flags |= WGDEVICE_F_REPLACE_PEERS;
		if (dev->flags & WGDEVICE_HAS_TRANSPORT)
			mnl_attr_put_u8(nlh, WGDEVICE_A_TRANSPORT, dev->transport);
		if (flags)
			mnl_attr_put_u32(nlh, WGDEVICE_A_FLAGS, flags);
	}
	if (!dev->first_peer)
		goto send;
	peers_nest = peer_nest = allowedips_nest = allowedip_nest = NULL;
	peers_nest = mnl_attr_nest_start(nlh, WGDEVICE_A_PEERS);
	for (peer = peer ? peer : dev->first_peer; peer; peer = peer->next_peer) {
		uint32_t flags = 0;

		peer_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, 0);
		if (!peer_nest)
			goto toobig_peers;
		if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PUBLIC_KEY, sizeof(peer->public_key), peer->public_key))
			goto toobig_peers;
		if (peer->flags & WGPEER_REMOVE_ME)
			flags |= WGPEER_F_REMOVE_ME;
		if (!allowedip) {
			if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
				flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
			if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PRESHARED_KEY, sizeof(peer->preshared_key), peer->preshared_key))
					goto toobig_peers;
			}
			if (peer->endpoint.addr.sa_family == AF_INET) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr4), &peer->endpoint.addr4))
					goto toobig_peers;
			} else if (peer->endpoint.addr.sa_family == AF_INET6) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr6), &peer->endpoint.addr6))
					goto toobig_peers;
			}
			if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) {
				if (!mnl_attr_put_u16_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer->persistent_keepalive_interval))
					goto toobig_peers;
			}
		}
		if (flags) {
			if (!mnl_attr_put_u32_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_FLAGS, flags))
				goto toobig_peers;
		}
		if (peer->first_allowedip) {
			if (!allowedip)
				allowedip = peer->first_allowedip;
			allowedips_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ALLOWEDIPS);
			if (!allowedips_nest)
				goto toobig_allowedips;
			for (; allowedip; allowedip = allowedip->next_allowedip) {
				allowedip_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, 0);
				if (!allowedip_nest)
					goto toobig_allowedips;
				if (!mnl_attr_put_u16_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_FAMILY, allowedip->family))
					goto toobig_allowedips;
				if (allowedip->family == AF_INET) {
					if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_IPADDR, sizeof(allowedip->ip4), &allowedip->ip4))
						goto toobig_allowedips;
				} else if (allowedip->family == AF_INET6) {
					if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_IPADDR, sizeof(allowedip->ip6), &allowedip->ip6))
						goto toobig_allowedips;
				}
				if (!mnl_attr_put_u8_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_CIDR_MASK, allowedip->cidr))
					goto toobig_allowedips;
				mnl_attr_nest_end(nlh, allowedip_nest);
				allowedip_nest = NULL;
			}
			mnl_attr_nest_end(nlh, allowedips_nest);
			allowedips_nest = NULL;
		}

		mnl_attr_nest_end(nlh, peer_nest);
		peer_nest = NULL;
	}
	mnl_attr_nest_end(nlh, peers_nest);
	peers_nest = NULL;
	goto send;
toobig_allowedips:
	if (allowedip_nest)
		mnl_attr_nest_cancel(nlh, allowedip_nest);
	if (allowedips_nest)
		mnl_attr_nest_end(nlh, allowedips_nest);
	mnl_attr_nest_end(nlh, peer_nest);
	mnl_attr_nest_end(nlh, peers_nest);
	goto send;
toobig_peers:
	if (peer_nest)
		mnl_attr_nest_cancel(nlh, peer_nest);
	mnl_attr_nest_end(nlh, peers_nest);
	goto send;
send:

	// Print the netlink message before sending it
	print_netlink_message_verbose(nlh);
	print_netlink_message_libmnl(nlh);

	if (mnlg_socket_send(nlg, nlh) < 0) {
		ret = -errno;
		goto out;
	}
	errno = 0;
	if (mnlg_socket_recv_run(nlg, NULL, NULL) < 0) {
		ret = errno ? -errno : -EINVAL;
		goto out;
	}
	if (peer)
		goto again;

out:
	mnlg_socket_close(nlg);
	errno = -ret;
	printf("Exiting kernel_set_device\n");
	return ret;
}

static int parse_allowedip(const struct nlattr *attr, void *data)
{
	struct wgallowedip *allowedip = data;

	print_allowedip_attr(attr);
	switch (mnl_attr_get_type(attr)) {
	case WGALLOWEDIP_A_UNSPEC:
		break;
	case WGALLOWEDIP_A_FAMILY:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			allowedip->family = mnl_attr_get_u16(attr);
		break;
	case WGALLOWEDIP_A_IPADDR:
		if (mnl_attr_get_payload_len(attr) == sizeof(allowedip->ip4))
			memcpy(&allowedip->ip4, mnl_attr_get_payload(attr), sizeof(allowedip->ip4));
		else if (mnl_attr_get_payload_len(attr) == sizeof(allowedip->ip6))
			memcpy(&allowedip->ip6, mnl_attr_get_payload(attr), sizeof(allowedip->ip6));
		break;
	case WGALLOWEDIP_A_CIDR_MASK:
		if (!mnl_attr_validate(attr, MNL_TYPE_U8))
			allowedip->cidr = mnl_attr_get_u8(attr);
		break;
	}

	return MNL_CB_OK;
}

static int parse_allowedips(const struct nlattr *attr, void *data)
{
	struct wgpeer *peer = data;
	struct wgallowedip *new_allowedip = calloc(1, sizeof(*new_allowedip));
	int ret;

	printf("Entering parse_allowedips\n");
	if (!new_allowedip) {
		perror("calloc");
		return MNL_CB_ERROR;
	}
	if (!peer->first_allowedip)
		peer->first_allowedip = peer->last_allowedip = new_allowedip;
	else {
		peer->last_allowedip->next_allowedip = new_allowedip;
		peer->last_allowedip = new_allowedip;
	}
	ret = mnl_attr_parse_nested(attr, parse_allowedip, new_allowedip);
	if (!ret)
		return ret;
	if (!((new_allowedip->family == AF_INET && new_allowedip->cidr <= 32) || (new_allowedip->family == AF_INET6 && new_allowedip->cidr <= 128)))
		return MNL_CB_ERROR;
	printf("Exiting parse_allowedips\n");
	return MNL_CB_OK;
}

static int parse_peer(const struct nlattr *attr, void *data)
{
	struct wgpeer *peer = data;

	print_peer_attr(attr);
	switch (mnl_attr_get_type(attr)) {
	case WGPEER_A_UNSPEC:
		break;
	case WGPEER_A_PUBLIC_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->public_key)) {
			memcpy(peer->public_key, mnl_attr_get_payload(attr), sizeof(peer->public_key));
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		}
		break;
	case WGPEER_A_PRESHARED_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->preshared_key)) {
			memcpy(peer->preshared_key, mnl_attr_get_payload(attr), sizeof(peer->preshared_key));
			if (!key_is_zero(peer->preshared_key))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		}
		break;
	case WGPEER_A_ENDPOINT: {
		struct sockaddr *addr;

		if (mnl_attr_get_payload_len(attr) < sizeof(*addr))
			break;
		addr = mnl_attr_get_payload(attr);
		if (addr->sa_family == AF_INET && mnl_attr_get_payload_len(attr) == sizeof(peer->endpoint.addr4))
			memcpy(&peer->endpoint.addr4, addr, sizeof(peer->endpoint.addr4));
		else if (addr->sa_family == AF_INET6 && mnl_attr_get_payload_len(attr) == sizeof(peer->endpoint.addr6))
			memcpy(&peer->endpoint.addr6, addr, sizeof(peer->endpoint.addr6));
		break;
	}
	case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			peer->persistent_keepalive_interval = mnl_attr_get_u16(attr);
		break;
	case WGPEER_A_LAST_HANDSHAKE_TIME:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->last_handshake_time))
			memcpy(&peer->last_handshake_time, mnl_attr_get_payload(attr), sizeof(peer->last_handshake_time));
		break;
	case WGPEER_A_RX_BYTES:
		if (!mnl_attr_validate(attr, MNL_TYPE_U64))
			peer->rx_bytes = mnl_attr_get_u64(attr);
		break;
	case WGPEER_A_TX_BYTES:
		if (!mnl_attr_validate(attr, MNL_TYPE_U64))
			peer->tx_bytes = mnl_attr_get_u64(attr);
		break;
	case WGPEER_A_ALLOWEDIPS:
		return mnl_attr_parse_nested(attr, parse_allowedips, peer);
		break;
	}

	return MNL_CB_OK;
}

static int parse_peers(const struct nlattr *attr, void *data)
{
	struct wgdevice *device = data;
	struct wgpeer *new_peer = calloc(1, sizeof(*new_peer));
	int ret;

	printf("Entering parse_peers\n");
	if (!new_peer) {
		perror("calloc");
		return MNL_CB_ERROR;
	}
	if (!device->first_peer)
		device->first_peer = device->last_peer = new_peer;
	else {
		device->last_peer->next_peer = new_peer;
		device->last_peer = new_peer;
	}
	ret = mnl_attr_parse_nested(attr, parse_peer, new_peer);
	if (!ret)
		return ret;
	if (!(new_peer->flags & WGPEER_HAS_PUBLIC_KEY))
		return MNL_CB_ERROR;
	printf("Exiting parse_peers\n");
	return MNL_CB_OK;
}

static int parse_device(const struct nlattr *attr, void *data)
{
	struct wgdevice *device = data;

	print_device_attr(attr);
	switch (mnl_attr_get_type(attr)) {
	case WGDEVICE_A_UNSPEC:
		break;
	case WGDEVICE_A_IFINDEX:
		if (!mnl_attr_validate(attr, MNL_TYPE_U32))
			device->ifindex = mnl_attr_get_u32(attr);
		break;
	case WGDEVICE_A_IFNAME:
		if (!mnl_attr_validate(attr, MNL_TYPE_STRING)) {
			strncpy(device->name, mnl_attr_get_str(attr), sizeof(device->name) - 1);
			device->name[sizeof(device->name) - 1] = '\0';
		}
		break;
	case WGDEVICE_A_PRIVATE_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(device->private_key)) {
			memcpy(device->private_key, mnl_attr_get_payload(attr), sizeof(device->private_key));
			device->flags |= WGDEVICE_HAS_PRIVATE_KEY;
		}
		break;
	case WGDEVICE_A_PUBLIC_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(device->public_key)) {
			memcpy(device->public_key, mnl_attr_get_payload(attr), sizeof(device->public_key));
			device->flags |= WGDEVICE_HAS_PUBLIC_KEY;
		}
		break;
	case WGDEVICE_A_LISTEN_PORT:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			device->listen_port = mnl_attr_get_u16(attr);
		break;
	case WGDEVICE_A_FWMARK:
		if (!mnl_attr_validate(attr, MNL_TYPE_U32))
			device->fwmark = mnl_attr_get_u32(attr);
		break;
	case WGDEVICE_A_TRANSPORT:
		if (!mnl_attr_validate(attr, MNL_TYPE_U8))
			device->transport = mnl_attr_get_u8(attr);
		break;
	case WGDEVICE_A_PEERS:
		return mnl_attr_parse_nested(attr, parse_peers, device);
	}

	return MNL_CB_OK;
}

static int read_device_cb(const struct nlmsghdr *nlh, void *data)
{
	printf("Entering read_device_cb\n");
	int ret = mnl_attr_parse(nlh, sizeof(struct genlmsghdr), parse_device, data);
	printf("Exiting read_device_cb\n");
	return ret;
}

static void coalesce_peers(struct wgdevice *device)
{
	struct wgpeer *old_next_peer, *peer = device->first_peer;

	printf("Entering coalesce_peers\n");
	while (peer && peer->next_peer) {
		if (memcmp(peer->public_key, peer->next_peer->public_key, sizeof(peer->public_key))) {
			peer = peer->next_peer;
			continue;
		}
		if (!peer->first_allowedip) {
			peer->first_allowedip = peer->next_peer->first_allowedip;
			peer->last_allowedip = peer->next_peer->last_allowedip;
		} else {
			peer->last_allowedip->next_allowedip = peer->next_peer->first_allowedip;
			peer->last_allowedip = peer->next_peer->last_allowedip;
		}
		old_next_peer = peer->next_peer;
		peer->next_peer = old_next_peer->next_peer;
		free(old_next_peer);
	}
	printf("Exiting coalesce_peers\n");
}

static int kernel_get_device(struct wgdevice **device, const char *iface)
{
	int ret;
	struct nlmsghdr *nlh;
	struct mnlg_socket *nlg;

	/* libmnl doesn't check the buffer size, so enforce that before using. */
	if (strlen(iface) >= IFNAMSIZ) {
		errno = ENAMETOOLONG;
		return -ENAMETOOLONG;
	}

try_again:
	ret = 0;
	*device = calloc(1, sizeof(**device));
	if (!*device)
		return -errno;

	nlg = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
	if (!nlg) {
		free_wgdevice(*device);
		*device = NULL;
		return -errno;
	}

	nlh = mnlg_msg_prepare(nlg, WG_CMD_GET_DEVICE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
	mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, iface);
	if (mnlg_socket_send(nlg, nlh) < 0) {
		ret = -errno;
		goto out;
	}
	errno = 0;
	if (mnlg_socket_recv_run(nlg, read_device_cb, *device) < 0) {
		ret = errno ? -errno : -EINVAL;
		goto out;
	}
	coalesce_peers(*device);

out:
	if (nlg)
		mnlg_socket_close(nlg);
	if (ret) {
		free_wgdevice(*device);
		if (ret == -EINTR)
			goto try_again;
		*device = NULL;
	}
	errno = -ret;
	printf("Exiting kernel_get_device\n");
	return ret;
}
