/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#ifndef _WG_SOCKET_H
#define _WG_SOCKET_H

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>

int wg_socket_init(struct wg_device *wg, u16 port);
void wg_socket_reinit(struct wg_device *wg, struct sock *new4,
		      struct sock *new6);
int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *data,
				  size_t len, u8 ds);
int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb,
					  void *out_buffer, size_t len);

int wg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb);
int wg_socket_send_skb_to_endpoint(struct wg_device *wg,
				   struct sk_buff *skb,
				   struct endpoint *endpoint, u8 ds,
				   struct dst_cache *cache);

struct wg_tcp_encap_header {
	__be32 length;
	__u8 type;
	__u8 flags;
	__be16 checksum;
};

struct wg_tcp_frag_header {
	__be16 id;
	__be16 frag_off;
};

struct wg_tcp_socket_list_entry {
	struct socket *tcp_socket; /* Socket associated with the connection */
	struct sockaddr_storage src_addr; /* Source address for the connection */
	struct wg_peer *temp_peer; /* temporary peer for dataready */
	struct list_head tcp_connection_ll; /* List pointer for the linked list */
	ktime_t created_at; /* Absolute pre-authentication deadline base */
	ktime_t timestamp; /* Most recent pre-authentication activity */
	u64 connection_id; /* Stable carrier identity across async auth */
	bool authenticated; /* Exact stream carried valid Noise traffic */
	bool admission_counted; /* Owns one pre-authentication reservation */
	bool initializing; /* Listener still owns callback handoff */
};

#define WG_TCP_ENCAP_HDR_LEN sizeof(struct wg_tcp_encap_header)
#define WG_TCP_FRAG_HDR_LEN sizeof(struct wg_tcp_frag_header)
#define WG_MAX_PACKET_SIZE 65535 + WG_TCP_ENCAP_HDR_LEN
#define WG_TCP_SKB_READ_ALLOC_SIZE 8192 * 3
/* A nominal 128 bytes to account for various
 * stacked headers in any given Ethernet frame
 */
#define WG_TCP_RESERVED_HEADER_SIZE 128
#define WG_TCP_RECORD_DATA 0
/* Flags */
#define WG_TCP_FRAG_FLAG 0x1

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_skb_ratelimited(fmt, dev, skb, ...) do {                       \
		struct endpoint __endpoint;                                    \
		wg_socket_endpoint_from_skb(&__endpoint, skb);                 \
		net_dbg_ratelimited(fmt, dev, &__endpoint.addr,                \
				    ##__VA_ARGS__);                            \
	} while (0)
#else
#define net_dbg_skb_ratelimited(fmt, skb, ...)
#endif

void wg_tcp_connection_retry_timer(struct timer_list *);

bool endpoint_eq(const struct endpoint *a, const struct endpoint *b);
void wg_print_wireguard_skb(const struct sk_buff *skb);

#endif /* _WG_SOCKET_H */
