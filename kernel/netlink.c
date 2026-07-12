// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#include "netlink.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"

#include <uapi/linux/wireguard.h>

#include <linux/if.h>
#include <linux/version.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <crypto/algapi.h>
#include <crypto/utils.h>
#include "wg_tcp_debug.h"

static struct genl_family genl_family;

static const struct nla_policy device_policy[WGDEVICE_A_MAX + 1] = {
	[WGDEVICE_A_IFINDEX]		= { .type = NLA_U32 },
	[WGDEVICE_A_IFNAME]		= { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[WGDEVICE_A_PRIVATE_KEY]	= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGDEVICE_A_PUBLIC_KEY]		= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGDEVICE_A_FLAGS]		= { .type = NLA_U32 },
	[WGDEVICE_A_LISTEN_PORT]	= { .type = NLA_U16 },
	[WGDEVICE_A_FWMARK]		= { .type = NLA_U32 },
	[WGDEVICE_A_PEERS]		= { .type = NLA_NESTED },
	[WGDEVICE_A_TRANSPORT]		= { .type = NLA_U8 }
};

static const struct nla_policy peer_policy[WGPEER_A_MAX + 1] = {
	[WGPEER_A_PUBLIC_KEY]				= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),
	[WGPEER_A_PRESHARED_KEY]			= NLA_POLICY_EXACT_LEN(NOISE_SYMMETRIC_KEY_LEN),
	[WGPEER_A_FLAGS]				= { .type = NLA_U32 },
	[WGPEER_A_ENDPOINT]				= NLA_POLICY_MIN_LEN(sizeof(struct sockaddr)),
	[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]	= { .type = NLA_U16 },
	[WGPEER_A_LAST_HANDSHAKE_TIME]			= NLA_POLICY_EXACT_LEN(sizeof(struct __kernel_timespec)),
	[WGPEER_A_RX_BYTES]				= { .type = NLA_U64 },
	[WGPEER_A_TX_BYTES]				= { .type = NLA_U64 },
	[WGPEER_A_ALLOWEDIPS]				= { .type = NLA_NESTED },
	[WGPEER_A_PROTOCOL_VERSION]			= { .type = NLA_U32 }
};

static const struct nla_policy allowedip_policy[WGALLOWEDIP_A_MAX + 1] = {
	[WGALLOWEDIP_A_FAMILY]		= { .type = NLA_U16 },
	[WGALLOWEDIP_A_IPADDR]		= NLA_POLICY_MIN_LEN(sizeof(struct in_addr)),
	[WGALLOWEDIP_A_CIDR_MASK]	= { .type = NLA_U8 }
};


#ifdef DIAGNOSTIC
// Diagnostic functions for decoding netlink attributes and messages

// Function to print the libmnl formatted netlink message header
static void wg_print_netlink_header_libmnl(const struct nlmsghdr *nlh)
{
    wg_dbg("----------------\t------------------\n");
    wg_dbg("|  %.010u  |\t| message length |\n", nlh->nlmsg_len);
    wg_dbg("| %.05u | %c%c%c%c |\t|  type | flags  |\n",
           nlh->nlmsg_type,
           nlh->nlmsg_flags & NLM_F_REQUEST ? 'R' : '-',
           nlh->nlmsg_flags & NLM_F_MULTI ? 'M' : '-',
           nlh->nlmsg_flags & NLM_F_ACK ? 'A' : '-',
           nlh->nlmsg_flags & NLM_F_ECHO ? 'E' : '-');
    wg_dbg("|  %.010u  |\t| sequence number|\n", nlh->nlmsg_seq);
    wg_dbg("|  %.010u  |\t|     port ID    |\n", nlh->nlmsg_pid);
    wg_dbg("----------------\t------------------\n");
}

// Function to print the libmnl formatted netlink message payload
static void wg_print_netlink_payload_libmnl(const struct nlmsghdr *nlh, size_t extra_header_size)
{
    unsigned int i;
    int rem = 0;

    for (i = sizeof(struct nlmsghdr); i < nlh->nlmsg_len; i += 4) {
        char *b = (char *)nlh;
        struct nlattr *attr = (struct nlattr *)(b + i);

        if (nlh->nlmsg_type < NLMSG_MIN_TYPE) {
            wg_dbg("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            wg_dbg("|                |\n");
        } else if (extra_header_size > 0) {
            extra_header_size -= 4;
            wg_dbg("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            wg_dbg("|  extra header  |\n");
        } else if (rem == 0 && (attr->nla_type & NLA_TYPE_MASK) != 0) {
            wg_dbg("|%.5u|%c%c|%.5u|\t",
                   attr->nla_len,
                   attr->nla_type & NLA_F_NESTED ? 'N' : '-',
                   attr->nla_type & NLA_F_NET_BYTEORDER ? 'B' : '-',
                   attr->nla_type & NLA_TYPE_MASK);
            wg_dbg("|len |flags| type|\n");

            if (!(attr->nla_type & NLA_F_NESTED)) {
                rem = NLA_ALIGN(attr->nla_len) - sizeof(struct nlattr);
            }
        } else if (rem > 0) {
            rem -= 4;
            wg_dbg("| %.2x %.2x %.2x %.2x  |\t",
                   0xff & b[i], 0xff & b[i + 1],
                   0xff & b[i + 2], 0xff & b[i + 3]);
            wg_dbg("|      data      |");
            wg_dbg("\t %c %c %c %c\n",
                   isprint(b[i]) ? b[i] : ' ',
                   isprint(b[i + 1]) ? b[i + 1] : ' ',
                   isprint(b[i + 2]) ? b[i + 2] : ' ',
                   isprint(b[i + 3]) ? b[i + 3] : ' ');
        }
    }
    wg_dbg("----------------\t------------------\n");
}

// Print the netlink message using libmnl format
static void wg_print_netlink_message_libmnl(const struct nlmsghdr *nlh)
{
    wg_print_netlink_header_libmnl(nlh);
    wg_print_netlink_payload_libmnl(nlh, 0);
}

// Routine to parse and print flags with verbose values
static void wg_print_flags_verbose(uint32_t flags)
{
    wg_dbg("Flags: 0x%08x (", flags);
    if (flags & NLM_F_REQUEST) wg_dbg("REQUEST ");
    if (flags & NLM_F_MULTI) wg_dbg("MULTI ");
    if (flags & NLM_F_ACK) wg_dbg("ACK ");
    if (flags & NLM_F_ECHO) wg_dbg("ECHO ");
    if (flags & NLM_F_REPLACE) wg_dbg("REPLACE ");
    if (flags & NLM_F_EXCL) wg_dbg("EXCL ");
    if (flags & NLM_F_CREATE) wg_dbg("CREATE ");
    if (flags & NLM_F_APPEND) wg_dbg("APPEND ");
    wg_dbg(")\n");
}

// Routine to parse and print peer flags with verbose labels
static void wg_print_peer_flags_verbose(uint32_t flags)
{
    wg_dbg("Peer Flags: 0x%08x (", flags);
    if (flags & WGPEER_F_REMOVE_ME) wg_dbg("REMOVE_ME ");
    if (flags & WGPEER_F_REPLACE_ALLOWEDIPS) wg_dbg("REPLACE_ALLOWEDIPS ");
    if (flags & WGPEER_F_UPDATE_ONLY) wg_dbg("UPDATE_ONLY ");
    wg_dbg(")\n");
}

// Functions to print the allowed IP attributes
static void wg_print_allowedip_attr(const struct nlattr *attr)
{
    int type = nla_type(attr);

    switch (type) {
    case WGALLOWEDIP_A_FAMILY:
        wg_dbg("WGALLOWEDIP_A_FAMILY: %u\n", nla_get_u16(attr));
        break;
    case WGALLOWEDIP_A_IPADDR:
        wg_dbg("WGALLOWEDIP_A_IPADDR: %pI6\n", nla_data(attr));
        break;
    case WGALLOWEDIP_A_CIDR_MASK:
        wg_dbg("WGALLOWEDIP_A_CIDR_MASK: %u\n", nla_get_u8(attr));
        break;
    default:
        wg_dbg("Unknown Allowed IP Attribute Type: %d\n", type);
        break;
    }
}

static void wg_print_peer_allowedips(const struct nlattr *attr)
{
    struct nlattr *nested_attr;
    int rem;

    nla_for_each_nested(nested_attr, attr, rem) {
        wg_print_allowedip_attr(nested_attr);
    }
}

// Functions to print the peer attributes
static void wg_print_peer_attr(const struct nlattr *attr)
{
    int type = nla_type(attr);

    switch (type) {
    case WGPEER_A_PUBLIC_KEY:
        wg_dbg("WGPEER_A_PUBLIC_KEY: %*phN\n", nla_len(attr), nla_data(attr));
        break;
    case WGPEER_A_PRESHARED_KEY:
        wg_dbg("WGPEER_A_PRESHARED_KEY: %*phN\n", nla_len(attr), nla_data(attr));
        break;
    case WGPEER_A_FLAGS:
        wg_dbg("WGPEER_A_FLAGS: %u\n", nla_get_u32(attr));
        wg_print_peer_flags_verbose(nla_get_u32(attr));
        break;
    case WGPEER_A_ENDPOINT:
        wg_dbg("WGPEER_A_ENDPOINT: %pIS\n", nla_data(attr));
        break;
    case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
        wg_dbg("WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: %u\n", nla_get_u16(attr));
        break;
    case WGPEER_A_LAST_HANDSHAKE_TIME: {
        const struct __kernel_timespec *ts = nla_data(attr);
        wg_dbg("WGPEER_A_LAST_HANDSHAKE_TIME: %lld.%.9ld\n",
               (long long)ts->tv_sec, ts->tv_nsec);
        break;
    }
    case WGPEER_A_RX_BYTES:
        wg_dbg("WGPEER_A_RX_BYTES: %llu\n", (unsigned long long)nla_get_u64(attr));
        break;
    case WGPEER_A_TX_BYTES:
        wg_dbg("WGPEER_A_TX_BYTES: %llu\n", (unsigned long long)nla_get_u64(attr));
        break;
    case WGPEER_A_ALLOWEDIPS:
        wg_dbg("WGPEER_A_ALLOWEDIPS (Nested Attributes):\n");
        wg_print_peer_allowedips(attr);
        break;
    default:
        wg_dbg("Unknown Peer Attribute Type: %d\n", type);
        break;
    }
}

// Functions to print the device attributes
static void wg_print_device_peers(const struct nlattr *attr)
{
    struct nlattr *nested_attr;
    int rem;

    nla_for_each_nested(nested_attr, attr, rem) {
        wg_print_peer_attr(nested_attr);
    }
}

static void wg_print_device_attr(const struct nlattr *attr)
{
    int type = nla_type(attr);

    switch (type) {
    case WGDEVICE_A_IFINDEX:
        wg_dbg("WGDEVICE_A_IFINDEX: %u\n", nla_get_u32(attr));
        break;
    case WGDEVICE_A_IFNAME:
        wg_dbg("WGDEVICE_A_IFNAME: %s\n", nla_data(attr));
        break;
    case WGDEVICE_A_PRIVATE_KEY:
        wg_dbg("WGDEVICE_A_PRIVATE_KEY: %*phN\n", nla_len(attr), nla_data(attr));
        break;
    case WGDEVICE_A_PUBLIC_KEY:
        wg_dbg("WGDEVICE_A_PUBLIC_KEY: %*phN\n", nla_len(attr), nla_data(attr));
        break;
    case WGDEVICE_A_FLAGS:
        wg_dbg("WGDEVICE_A_FLAGS: %u\n", nla_get_u32(attr));
        break;
    case WGDEVICE_A_LISTEN_PORT:
        wg_dbg("WGDEVICE_A_LISTEN_PORT: %u\n", nla_get_u16(attr));
        break;
    case WGDEVICE_A_FWMARK:
        wg_dbg("WGDEVICE_A_FWMARK: %u\n", nla_get_u32(attr));
        break;
    case WGDEVICE_A_PEERS:
        wg_dbg("WGDEVICE_A_PEERS (Nested Attributes):\n");
        wg_print_device_peers(attr);
        break;
    case WGDEVICE_A_TRANSPORT:
        wg_dbg("WGDEVICE_A_TRANSPORT: %u\n", nla_get_u8(attr));
        break;
    default:
        wg_dbg("Unknown Device Attribute Type: %d\n", type);
        break;
    }
}

static void wg_print_netlink_message_verbose(const struct nlmsghdr *nlh)
{
    struct nlattr *attr;
    int rem;

    wg_dbg("Verbose Netlink Message:\n");
    wg_dbg("  nlmsg_len: %u\n", nlh->nlmsg_len);
    wg_dbg("  nlmsg_type: %u\n", nlh->nlmsg_type);

    // Print command
    switch (nlh->nlmsg_type) {
    case WG_CMD_GET_DEVICE:
        wg_dbg("  Command: WG_CMD_GET_DEVICE\n");
        break;
    case WG_CMD_SET_DEVICE:
        wg_dbg("  Command: WG_CMD_SET_DEVICE\n");
        break;
    default:
        wg_dbg("  Unknown Command: %u\n", nlh->nlmsg_type);
        break;
    }

    wg_print_flags_verbose(nlh->nlmsg_flags);
    wg_dbg("  nlmsg_seq: %u\n", nlh->nlmsg_seq);
    wg_dbg("  nlmsg_pid: %u\n", nlh->nlmsg_pid);
    wg_dbg("Attributes:\n");

    nla_for_each_attr(attr, nlmsg_data(nlh), nlmsg_len(nlh) - NLMSG_HDRLEN, rem) {
        switch (nlh->nlmsg_type) {
        case WG_CMD_GET_DEVICE:
        case WG_CMD_SET_DEVICE:
            wg_print_device_attr(attr);
            break;
        default:
            wg_dbg("Unknown Netlink Message Type: %u\n", nlh->nlmsg_type);
            break;
        }
    }

    wg_dbg("Hex Dump of Netlink Message:\n");
    wg_dbg("%*phN\n", nlh->nlmsg_len, nlh);
}

// Add a function to print the entire buffer of netlink messages
static void wg_print_netlink_buffer(const void *buf, size_t len)
{
    const struct nlmsghdr *nlh = buf;

    while (nlh && NLMSG_OK(nlh, len)) {
        wg_print_netlink_message_verbose(nlh);
        wg_print_netlink_message_libmnl(nlh);
        nlh = NLMSG_NEXT(nlh, len);
    }
}

#endif // DIAGNOSTIC

static struct wg_device *lookup_interface(struct nlattr **attrs, struct sk_buff *skb)
{
	struct net_device *dev = NULL;

	wg_dbg("Entering lookup_interface: attrs = %px, skb = %px\n", attrs, skb);

	if (!attrs[WGDEVICE_A_IFINDEX] == !attrs[WGDEVICE_A_IFNAME])
		return ERR_PTR(-EBADR);
	if (attrs[WGDEVICE_A_IFINDEX])
		dev = dev_get_by_index(sock_net(skb->sk), nla_get_u32(attrs[WGDEVICE_A_IFINDEX]));
	else if (attrs[WGDEVICE_A_IFNAME])
		dev = dev_get_by_name(sock_net(skb->sk), nla_data(attrs[WGDEVICE_A_IFNAME]));
	if (!dev)
		return ERR_PTR(-ENODEV);
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);
		return ERR_PTR(-EOPNOTSUPP);
	}

	wg_dbg("Exiting lookup_interface\n");

	return netdev_priv(dev);
}

static int get_allowedips(struct sk_buff *skb, const u8 *ip, u8 cidr, int family)
{
	struct nlattr *allowedip_nest;

	wg_dbg("Entering get_allowedips: skb = %px, ip = %px, cidr = %u, family = %d\n", skb, ip, cidr, family);

	allowedip_nest = nla_nest_start(skb, 0);
	if (!allowedip_nest)
		return -EMSGSIZE;

	if (nla_put_u8(skb, WGALLOWEDIP_A_CIDR_MASK, cidr) ||
	    nla_put_u16(skb, WGALLOWEDIP_A_FAMILY, family) ||
	    nla_put(skb, WGALLOWEDIP_A_IPADDR, family == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr), ip)) {
		nla_nest_cancel(skb, allowedip_nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, allowedip_nest);

	wg_dbg("Exiting get_allowedips\n");

	return 0;
}

struct dump_ctx {
	struct wg_device *wg;
	struct wg_peer *next_peer;
	u64 allowedips_seq;
	struct allowedips_node *next_allowedip;
};

#define DUMP_CTX(cb) ((struct dump_ctx *)(cb)->args)

static int get_peer(struct wg_peer *peer, struct sk_buff *skb, struct dump_ctx *ctx)
{
	struct nlattr *allowedips_nest, *peer_nest = nla_nest_start(skb, 0);
	struct allowedips_node *allowedips_node = ctx->next_allowedip;
	bool fail;

	wg_dbg("Entering get_peer: peer = %px, skb = %px, ctx = %px\n", peer, skb, ctx);

	if (!peer_nest)
		return -EMSGSIZE;

	down_read(&peer->handshake.lock);
	fail = nla_put(skb, WGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN, peer->handshake.remote_static);
	up_read(&peer->handshake.lock);
	if (fail)
		goto err;

	if (!allowedips_node) {
		const struct __kernel_timespec last_handshake = {
			.tv_sec = peer->walltime_last_handshake.tv_sec,
			.tv_nsec = peer->walltime_last_handshake.tv_nsec
		};

		down_read(&peer->handshake.lock);
		fail = nla_put(skb, WGPEER_A_PRESHARED_KEY, NOISE_SYMMETRIC_KEY_LEN, peer->handshake.preshared_key);
		up_read(&peer->handshake.lock);
		if (fail)
			goto err;

		if (nla_put(skb, WGPEER_A_LAST_HANDSHAKE_TIME, sizeof(last_handshake), &last_handshake) ||
		    nla_put_u16(skb, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer->persistent_keepalive_interval) ||
		    nla_put_u64_64bit(skb, WGPEER_A_TX_BYTES, peer->tx_bytes, WGPEER_A_UNSPEC) ||
		    nla_put_u64_64bit(skb, WGPEER_A_RX_BYTES, peer->rx_bytes, WGPEER_A_UNSPEC) ||
		    nla_put_u32(skb, WGPEER_A_PROTOCOL_VERSION, 1))
			goto err;

		read_lock_bh(&peer->endpoint_lock);
		if (peer->endpoint.addr.sa_family == AF_INET)
			fail = nla_put(skb, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr4), &peer->endpoint.addr4);
		else if (peer->endpoint.addr.sa_family == AF_INET6)
			fail = nla_put(skb, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr6), &peer->endpoint.addr6);
		read_unlock_bh(&peer->endpoint_lock);
		if (fail)
			goto err;
		allowedips_node = list_first_entry_or_null(&peer->allowedips_list, struct allowedips_node, peer_list);
	}
	if (!allowedips_node)
		goto no_allowedips;
	if (!ctx->allowedips_seq)
		ctx->allowedips_seq = peer->device->peer_allowedips.seq;
	else if (ctx->allowedips_seq != peer->device->peer_allowedips.seq)
		goto no_allowedips;

	allowedips_nest = nla_nest_start(skb, WGPEER_A_ALLOWEDIPS);
	if (!allowedips_nest)
		goto err;

	list_for_each_entry_from(allowedips_node, &peer->allowedips_list, peer_list) {
		u8 cidr, ip[16] __aligned(__alignof__(u64));
		int family;

		family = wg_allowedips_read_node(allowedips_node, ip, &cidr);
		if (get_allowedips(skb, ip, cidr, family)) {
			nla_nest_end(skb, allowedips_nest);
			nla_nest_end(skb, peer_nest);
			ctx->next_allowedip = allowedips_node;
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, allowedips_nest);
no_allowedips:
	nla_nest_end(skb, peer_nest);
	ctx->next_allowedip = NULL;
	ctx->allowedips_seq = 0;

	wg_dbg("Exiting get_peer\n");

	return 0;
err:
	nla_nest_cancel(skb, peer_nest);
	return -EMSGSIZE;
}

static int wg_get_device_start(struct netlink_callback *cb)
{
	struct wg_device *wg;

	wg_dbg("Entering wg_get_device_start: cb = %px\n", cb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	wg = lookup_interface(genl_info_dump(cb)->attrs, cb->skb);
#else
	wg = lookup_interface(genl_dumpit_info(cb)->attrs, cb->skb);
#endif
	if (IS_ERR(wg))
		return PTR_ERR(wg);
	DUMP_CTX(cb)->wg = wg;

	wg_dbg("Exiting wg_get_device_start\n");

	return 0;
}

static int wg_get_device_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct wg_peer *peer, *next_peer_cursor;
	struct dump_ctx *ctx = DUMP_CTX(cb);
	struct wg_device *wg = ctx->wg;
	struct nlattr *peers_nest;
	int ret = -EMSGSIZE;
	bool done = true;
	void *hdr;

	wg_dbg("Entering wg_get_device_dump: skb = %px, cb = %px\n", skb, cb);

	rtnl_lock();
	mutex_lock(&wg->device_update_lock);
	cb->seq = wg->device_update_gen;
	next_peer_cursor = ctx->next_peer;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &genl_family, NLM_F_MULTI, WG_CMD_GET_DEVICE);
	if (!hdr)
		goto out;
	genl_dump_check_consistent(cb, hdr);

	if (!ctx->next_peer) {
		if (nla_put_u16(skb, WGDEVICE_A_LISTEN_PORT, wg->incoming_port) ||
		    nla_put_u32(skb, WGDEVICE_A_FWMARK, wg->fwmark) ||
		    nla_put_u32(skb, WGDEVICE_A_IFINDEX, wg->dev->ifindex) ||
		    nla_put_string(skb, WGDEVICE_A_IFNAME, wg->dev->name) ||
		    nla_put_u8(skb, WGDEVICE_A_TRANSPORT, wg->transport))
			goto out;

		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity) {
			if (nla_put(skb, WGDEVICE_A_PRIVATE_KEY, NOISE_PUBLIC_KEY_LEN, wg->static_identity.static_private) ||
			    nla_put(skb, WGDEVICE_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN, wg->static_identity.static_public)) {
				up_read(&wg->static_identity.lock);
				goto out;
			}
		}
		up_read(&wg->static_identity.lock);
	}

	peers_nest = nla_nest_start(skb, WGDEVICE_A_PEERS);
	if (!peers_nest)
		goto out;

	ret = 0;
	/* If the last cursor was removed via list_del_init in peer_remove, then
	 * we just treat this the same as there being no more peers left. The
	 * reason is that seq_nr should indicate to userspace that this isn't a
	 * coherent dump anyway, so they'll try again.
	 */
	if (list_empty(&wg->peer_list) ||
	    (ctx->next_peer && list_empty(&ctx->next_peer->peer_list))) {
		nla_nest_cancel(skb, peers_nest);
		goto out;
	}
	lockdep_assert_held(&wg->device_update_lock);
	peer = list_prepare_entry(ctx->next_peer, &wg->peer_list, peer_list);
	list_for_each_entry_continue(peer, &wg->peer_list, peer_list) {
		if (get_peer(peer, skb, ctx)) {
			done = false;
			break;
		}
		next_peer_cursor = peer;
	}
	nla_nest_end(skb, peers_nest);

out:
	if (!ret && !done && next_peer_cursor)
		wg_peer_get(next_peer_cursor);
	wg_peer_put(ctx->next_peer);
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();

	if (ret) {
		genlmsg_cancel(skb, hdr);
		return ret;
	}
	genlmsg_end(skb, hdr);
	if (done) {
		ctx->next_peer = NULL;

		wg_dbg("Exiting wg_get_device_dump\n");

		return 0;
	}
	ctx->next_peer = next_peer_cursor;

	wg_dbg("Exiting wg_get_device_dump\n");

	return skb->len;

	/* At this point, we can't really deal ourselves with safely zeroing out
	 * the private key material after usage. This will need an additional API
	 * in the kernel for marking skbs as zero_on_free.
	 */
}

static int wg_get_device_done(struct netlink_callback *cb)
{
	struct dump_ctx *ctx = DUMP_CTX(cb);

	wg_dbg("Entering wg_get_device_done: cb = %px\n", cb);

	if (ctx->wg)
		dev_put(ctx->wg->dev);
	wg_peer_put(ctx->next_peer);

	wg_dbg("Exiting wg_get_device_done\n");

	return 0;
}

static int set_port(struct wg_device *wg, u16 port)
{
	struct wg_peer *peer;
	
	wg_dbg("Entering set_port: wg = %px, port = %u\n", wg, port);

	if (wg->incoming_port == port)
		return 0;
	/* Replacing both TCP listeners is not transactional. Require a down/up
	 * cycle and leave the active listeners completely untouched.
	 */
	if (wg->transport == WG_TRANSPORT_TCP && netif_running(wg->dev))
		return -EBUSY;
	list_for_each_entry(peer, &wg->peer_list, peer_list)
		wg_socket_clear_peer_endpoint_src(peer);
	if (!netif_running(wg->dev)) {
		wg->incoming_port = port;
		return 0;
	}

	return wg_socket_init(wg, port);
}

static int set_allowedip(struct wg_peer *peer, struct nlattr **attrs)
{
	int ret = -EINVAL;
	u16 family;
	u8 cidr;

	wg_dbg("Entering set_allowedip: peer = %px, attrs = %px\n", peer, attrs);

	if (!attrs[WGALLOWEDIP_A_FAMILY] || !attrs[WGALLOWEDIP_A_IPADDR] ||
	    !attrs[WGALLOWEDIP_A_CIDR_MASK])
		return ret;
	family = nla_get_u16(attrs[WGALLOWEDIP_A_FAMILY]);
	cidr = nla_get_u8(attrs[WGALLOWEDIP_A_CIDR_MASK]);

	if (family == AF_INET && cidr <= 32 &&
	    nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in_addr))
		ret = wg_allowedips_insert_v4(&peer->device->peer_allowedips, nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer, &peer->device->device_update_lock);
	else if (family == AF_INET6 && cidr <= 128 &&
		 nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in6_addr))
		ret = wg_allowedips_insert_v6(&peer->device->peer_allowedips, nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer, &peer->device->device_update_lock);

//	wg_dbg("Exiting set_allowedip\n");

	return ret;
}

static int set_peer(struct wg_device *wg, struct nlattr **attrs)
{
	u8 *public_key = NULL, *preshared_key = NULL;
	struct wg_peer *peer = NULL;
	u32 flags = 0;
	int ret;

	wg_dbg("Entering set_peer: wg = %px, attrs = %px\n", wg, attrs);

	ret = -EINVAL;
	if (attrs[WGPEER_A_PUBLIC_KEY] &&
	    nla_len(attrs[WGPEER_A_PUBLIC_KEY]) == NOISE_PUBLIC_KEY_LEN)
		public_key = nla_data(attrs[WGPEER_A_PUBLIC_KEY]);
	else
		goto out;
	if (attrs[WGPEER_A_PRESHARED_KEY] &&
	    nla_len(attrs[WGPEER_A_PRESHARED_KEY]) == NOISE_SYMMETRIC_KEY_LEN)
		preshared_key = nla_data(attrs[WGPEER_A_PRESHARED_KEY]);

	if (attrs[WGPEER_A_FLAGS])
		flags = nla_get_u32(attrs[WGPEER_A_FLAGS]);
	ret = -EOPNOTSUPP;
	if (flags & ~__WGPEER_F_ALL)
		goto out;

	ret = -EPFNOSUPPORT;
	if (attrs[WGPEER_A_PROTOCOL_VERSION]) {
		if (nla_get_u32(attrs[WGPEER_A_PROTOCOL_VERSION]) != 1)
			goto out;
	}

	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, nla_data(attrs[WGPEER_A_PUBLIC_KEY]));
	ret = 0;
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		if (flags & (WGPEER_F_REMOVE_ME | WGPEER_F_UPDATE_ONLY))
			goto out;

		/* The peer is new, so there aren't allowed IPs to remove. */
		flags &= ~WGPEER_F_REPLACE_ALLOWEDIPS;

		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity &&
		    !memcmp(nla_data(attrs[WGPEER_A_PUBLIC_KEY]), wg->static_identity.static_public, NOISE_PUBLIC_KEY_LEN)) {
			/* We silently ignore peers that have the same public
			 * key as the device. The reason we do it silently is
			 * that we'd like for people to be able to reuse the
			 * same set of API calls across peers.
			 */
			up_read(&wg->static_identity.lock);
			ret = 0;
			goto out;
		}
		up_read(&wg->static_identity.lock);

		peer = wg_peer_create(wg, public_key, preshared_key);
		if (IS_ERR(peer)) {
			ret = PTR_ERR(peer);
			peer = NULL;
			goto out;
		}
		/* Take additional reference, as though we've just been
		 * looked up.
		 */
		wg_peer_get(peer);
	}

	if (flags & WGPEER_F_REMOVE_ME) {
		wg_peer_remove(peer);
		goto out;
	}

	if (preshared_key) {
		down_write(&peer->handshake.lock);
		memcpy(&peer->handshake.preshared_key, preshared_key, NOISE_SYMMETRIC_KEY_LEN);
		up_write(&peer->handshake.lock);
	}

	if (attrs[WGPEER_A_ENDPOINT]) {
		struct sockaddr *addr = nla_data(attrs[WGPEER_A_ENDPOINT]);
		size_t len = nla_len(attrs[WGPEER_A_ENDPOINT]);
		struct endpoint endpoint = { { { 0 } } };

		if (len == sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
			endpoint.addr4 = *(struct sockaddr_in *)addr;
			wg_socket_set_peer_endpoint_configured(peer, &endpoint);
		} else if (len == sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			endpoint.addr6 = *(struct sockaddr_in6 *)addr;
			wg_socket_set_peer_endpoint_configured(peer, &endpoint);
		}
	}

	if (flags & WGPEER_F_REPLACE_ALLOWEDIPS)
		wg_allowedips_remove_by_peer(&wg->peer_allowedips, peer, &wg->device_update_lock);

	if (attrs[WGPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr, *allowedip[WGALLOWEDIP_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, attrs[WGPEER_A_ALLOWEDIPS], rem) {
			ret = nla_parse_nested(allowedip, WGALLOWEDIP_A_MAX, attr, allowedip_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_allowedip(peer, allowedip);
			if (ret < 0)
				goto out;
		}
	}

	if (attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
		const u16 persistent_keepalive_interval = nla_get_u16(attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		const bool send_keepalive = !peer->persistent_keepalive_interval && persistent_keepalive_interval && netif_running(wg->dev);

		peer->persistent_keepalive_interval = persistent_keepalive_interval;
		if (send_keepalive)
			wg_packet_send_keepalive(peer);
	}

	if (netif_running(wg->dev))
		wg_packet_send_staged_packets(peer);

out:
	wg_peer_put(peer);
	if (attrs[WGPEER_A_PRESHARED_KEY])
		memzero_explicit(nla_data(attrs[WGPEER_A_PRESHARED_KEY]), nla_len(attrs[WGPEER_A_PRESHARED_KEY]));

//	wg_dbg("Exiting set_peer\n");

	return ret;
}

static int wg_set_device(struct sk_buff *skb, struct genl_info *info)
{
	struct wg_device *wg;
	u32 flags = 0;
	int ret;

	wg_dbg("Entering wg_set_device: skb = %px, info = %px\n", skb, info);

#ifdef DIAGNOSTC	
	// Decode and print the netlink message received
	wg_print_netlink_buffer(skb, skb->len);
#endif
	
	wg = lookup_interface(info->attrs, skb);
	if (IS_ERR(wg)) {
		ret = PTR_ERR(wg);
		wg_dbg("Error in lookup_interface: %d\n", ret);
		goto out_nodev;
	}

	rtnl_lock();
	mutex_lock(&wg->device_update_lock);

	if (info->attrs[WGDEVICE_A_FLAGS]) {
		flags = nla_get_u32(info->attrs[WGDEVICE_A_FLAGS]);
//		wg_dbg("Parsed WGDEVICE_A_FLAGS: %u\n", flags);
	}
	ret = -EOPNOTSUPP;
	if (flags & ~__WGDEVICE_F_ALL)
		goto out;

	if (info->attrs[WGDEVICE_A_LISTEN_PORT] ||
	    info->attrs[WGDEVICE_A_FWMARK] ||
	    info->attrs[WGDEVICE_A_TRANSPORT]) {
		struct net *net;
		rcu_read_lock();
		net = rcu_dereference(wg->creating_net);
		ret = !net || !ns_capable(net->user_ns, CAP_NET_ADMIN) ? -EPERM : 0;
		rcu_read_unlock();
		if (ret) {
			wg_dbg("Permission error for NET_ADMIN capability: %d\n", ret);
			goto out;
		}
	}

	if (info->attrs[WGDEVICE_A_TRANSPORT]) {
		u8 transport = nla_get_u8(info->attrs[WGDEVICE_A_TRANSPORT]);

		if (transport > WG_TRANSPORT_TCP) {
			ret = -EINVAL;
			goto out;
		}
		if (transport != wg->transport) {
			if (netif_running(wg->dev) ||
			    (!list_empty(&wg->peer_list) &&
			     !(flags & WGDEVICE_F_REPLACE_PEERS))) {
				ret = -EBUSY;
				goto out;
			}
			wg->transport = transport;
		}
	}

	++wg->device_update_gen;

	if (info->attrs[WGDEVICE_A_FWMARK]) {
		struct wg_peer *peer;
		wg->fwmark = nla_get_u32(info->attrs[WGDEVICE_A_FWMARK]);
//		wg_dbg("Parsed WGDEVICE_A_FWMARK: %u\n", wg->fwmark);
		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_socket_clear_peer_endpoint_src(peer);
	}

	if (info->attrs[WGDEVICE_A_LISTEN_PORT]) {
		ret = set_port(wg, nla_get_u16(info->attrs[WGDEVICE_A_LISTEN_PORT]));
//		wg_dbg("Parsed WGDEVICE_A_LISTEN_PORT: %u, result: %d\n", nla_get_u16(info->attrs[WGDEVICE_A_LISTEN_PORT]), ret);
		if (ret)
			goto out;
	}

	if (flags & WGDEVICE_F_REPLACE_PEERS) {
//		wg_dbg("Replacing all peers\n");
		wg_peer_remove_all(wg);
	}

	if (info->attrs[WGDEVICE_A_PRIVATE_KEY] &&
	    nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]) == NOISE_PUBLIC_KEY_LEN) {
		u8 *private_key = nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]);
		u8 public_key[NOISE_PUBLIC_KEY_LEN];
		struct wg_peer *peer, *temp;
		bool send_staged_packets;

//		wg_dbg("Parsed WGDEVICE_A_PRIVATE_KEY\n");

		if (!crypto_memneq(wg->static_identity.static_private, private_key, NOISE_PUBLIC_KEY_LEN))
			goto skip_set_private_key;

		/* We remove before setting, to prevent race, which means doing
		 * two 25519-genpub ops.
		 */
		if (curve25519_generate_public(public_key, private_key)) {
			peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, public_key);
			if (peer) {
				wg_peer_put(peer);
				wg_peer_remove(peer);
			}
		}

		down_write(&wg->static_identity.lock);
		send_staged_packets = !wg->static_identity.has_identity && netif_running(wg->dev);
		wg_noise_set_static_identity_private_key(&wg->static_identity, private_key);
		send_staged_packets = send_staged_packets && wg->static_identity.has_identity;

		wg_cookie_checker_precompute_device_keys(&wg->cookie_checker);
		list_for_each_entry_safe(peer, temp, &wg->peer_list, peer_list) {
			wg_noise_precompute_static_static(peer);
			wg_noise_expire_current_peer_keypairs(peer);
			if (send_staged_packets)
				wg_packet_send_staged_packets(peer);
		}
		up_write(&wg->static_identity.lock);
	}

skip_set_private_key:
	if (info->attrs[WGDEVICE_A_PEERS]) {
		struct nlattr *attr, *peer[WGPEER_A_MAX + 1];
		int rem;

//		wg_dbg("Processing WGDEVICE_A_PEERS\n");

		nla_for_each_nested(attr, info->attrs[WGDEVICE_A_PEERS], rem) {
			ret = nla_parse_nested(peer, WGPEER_A_MAX, attr, peer_policy, NULL);
			if (ret < 0) {
				wg_dbg("Error parsing nested peer attributes: %d\n", ret);
				goto out;
			}
			ret = set_peer(wg, peer);
			if (ret < 0) {
				wg_dbg("Error setting peer: %d\n", ret);
				goto out;
			}
		}
	}
	ret = 0;

out:
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();
	dev_put(wg->dev);
out_nodev:
	if (info->attrs[WGDEVICE_A_PRIVATE_KEY])
		memzero_explicit(nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]), nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]));

	wg_dbg("Exiting wg_set_device\n");

	return ret;
}

static const struct genl_ops genl_ops[] = {
	{
		.cmd = WG_CMD_GET_DEVICE,
		.start = wg_get_device_start,
		.dumpit = wg_get_device_dump,
		.done = wg_get_device_done,
		.flags = GENL_UNS_ADMIN_PERM
	},
	{
		.cmd = WG_CMD_SET_DEVICE,
		.doit = wg_set_device,
		.flags = GENL_UNS_ADMIN_PERM
	}
};

static struct genl_family genl_family __ro_after_init = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
	.resv_start_op = WG_CMD_SET_DEVICE + 1,
	.name = WG_GENL_NAME,
	.version = WG_GENL_VERSION,
	.maxattr = WGDEVICE_A_MAX,
	.module = THIS_MODULE,
	.policy = device_policy,
	.netnsok = true
};

int __init wg_genetlink_init(void)
{
	wg_dbg("Entering wg_genetlink_init\n");

	int ret = genl_register_family(&genl_family);

	wg_dbg("Exiting wg_genetlink_init\n");

	return ret;
}

void __exit wg_genetlink_uninit(void)
{
	wg_dbg("Entering wg_genetlink_uninit\n");

	genl_unregister_family(&genl_family);

	wg_dbg("Exiting wg_genetlink_uninit\n");
}
