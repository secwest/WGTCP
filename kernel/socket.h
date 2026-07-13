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
int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb,
			       u8 ds);
int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb,
					  void *out_buffer, size_t len);

int wg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb);
void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb);
void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer);
void wg_destruct_tcp_connection_list(struct wg_device *wg);

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

#define WG_TCP_ENCAP_HDR_LEN sizeof(struct wg_tcp_encap_header)
#define WG_TCP_FRAG_HDR_LEN sizeof(struct wg_tcp_frag_header)
#define WG_MAX_PACKET_SIZE 65535 + WG_TCP_ENCAP_HDR_LEN
#define WG_TCP_SKB_READ_ALLOC_SIZE 8192 * 3
/* A nominal 128 bytes to account for various
 * stacked headers in any given Ethernet frame
 */
#define WG_TCP_RESERVED_HEADER_SIZE 128
#define WG_TCP_RECORD_DATA 0
// Flags 
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

/* Forward declarations of functions */
int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds);
int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *buffer, size_t len, u8 ds);
int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg, struct sk_buff *in_skb, void *buffer, size_t len);
int wg_socket_endpoint_from_skb(struct endpoint *endpoint, const struct sk_buff *skb);
void wg_socket_set_peer_endpoint(struct wg_peer *peer, const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_configured(struct wg_peer *peer,
					    const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_authenticated(struct wg_peer *peer,
					       const struct endpoint *endpoint,
					       u64 connection_id);
void wg_socket_set_peer_endpoint_authenticated_from_skb(
	struct wg_peer *peer, const struct sk_buff *skb);
void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer, const struct sk_buff *skb);
void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer);
void wg_socket_reinit(struct wg_device *wg, struct sock *new4, struct sock *new6);
void wg_tcp_state_change(struct sock *sk);
void wg_extract_endpoint_from_sock(struct sock *sk, struct endpoint *endpoint);
bool wg_check_potential_header_validity(struct wg_tcp_encap_header *hdr, size_t remaining_len);

int wg_tcp_queuepkt(struct wg_peer *, const void *, size_t);
void wg_tcp_write_space(struct sock *sk);
void wg_tcp_data_ready(struct sock *sk);

int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *sock,
			      struct wg_peer *temp_peer);
void wg_remove_from_tcp_connection_list(struct wg_device *wg, struct socket *sock);
void wg_destruct_tcp_connection_list(struct wg_device *wg);

int wg_tcp_listener_socket_init(struct wg_device *wg, u16 port);
void wg_tcp_listener_socket_release(struct wg_device *wg);

void wg_tcp_connection_retry_timer(struct timer_list *);
int wg_tcp_connect(struct wg_peer *);

int wg_tcp_listener_worker(struct wg_device *wg, struct socket *tcp_socket);
int wg_setup_tcp_listen4(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket);
int wg_setup_tcp_listen6(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket);
int wg_tcp_listener4_thread(void *data);
int wg_tcp_listener6_thread(void *data);

void wg_clean_peer_socket(struct wg_peer *peer, bool release, bool destroy, bool inbound);
void wg_tcp_peer_stop(struct wg_peer *peer);
void wg_tcp_peer_request_reconnect(struct wg_peer *peer);
void wg_tcp_set_device_mark(struct wg_device *wg, u32 mark);
void wg_tcp_write_worker(struct work_struct *work);
void wg_tcp_read_worker(struct work_struct *work);
void wg_tcp_cleanup_worker(struct work_struct *work);

/* FIX: -Wmissing-prototypes — cross-file function declarations */
bool endpoint_eq(const struct endpoint *a, const struct endpoint *b);
void print_peer_socket_info(struct wg_peer *peer);
void decode_and_print_packet(const struct sk_buff *skb, const char *prefix);
void wg_print_wireguard_skb(const struct sk_buff *skb);

#endif /* _WG_SOCKET_H */
