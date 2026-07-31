// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024-2026 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */
/*
 * WireGuard TCP Debug Macros
 *
 * Two independent levels, enabled via compiler flags:
 *
 *   -DWG_TCP_VERBOSE   Very verbose: function enter/exit traces, parameter
 *                       dumps, packet header parsing. Extremely noisy.
 *
 *   -DWG_TCP_DIAG      TCP performance diagnostics: per-packet socket state
 *                       dumps (cwnd, rtt, retrans, etc). Useful for debugging
 *                       throughput and congestion issues.
 *
 * Build examples (add to Makefile ccflags-y or command line):
 *   make ... EXTRA_CFLAGS="-DWG_TCP_VERBOSE -DWG_TCP_DIAG"   # everything
 *   make ... EXTRA_CFLAGS="-DWG_TCP_DIAG"                     # perf diag only
 *   make ...                                                    # no debug
 *
 * Error messages (KERN_ERR / pr_err) are always compiled in.
 */

#ifndef _WG_TCP_DEBUG_H
#define _WG_TCP_DEBUG_H

#include <linux/icmp.h>
#include <linux/atomic.h>
#include <linux/types.h>

#ifdef WG_TCP_VERBOSE
#define wg_dbg(fmt, ...)	printk(KERN_INFO fmt, ##__VA_ARGS__)
#else
#define wg_dbg(fmt, ...)	do {} while (0)
#endif

#ifdef WG_TCP_DIAG
#define wg_diag(fmt, ...)	pr_info(fmt, ##__VA_ARGS__)
#define WG_TCP_DIAG_ENABLED	1
#else
#define wg_diag(fmt, ...)	do {} while (0)
#define WG_TCP_DIAG_ENABLED	0
#endif

struct sk_buff;
struct crypt_queue;
struct sk_buff_head;
struct sock;
struct socket;
struct wg_device;
struct wg_peer;

void debug_skb(const struct sk_buff *askb);
void debug_wireguard_packet(const unsigned char *data,
                                   size_t payload_len);
void debug_wireguard_skb(const struct sk_buff *skb);
void debug_wireguard_tcp_mtu(struct sk_buff *skb, const char *location);

void decode_icmp_echo(const struct icmphdr *icmp_header);
void decode_icmp_dest_unreachable(const struct icmphdr *icmp_header);
void decode_icmp_time_exceeded(const struct icmphdr *icmp_header);
void decode_icmp_other(const struct icmphdr *icmp_header);
void decode_and_print_packet(const struct sk_buff *skb, const char *prefix);

void print_wg_peer(struct wg_peer *peer);
void print_crypt_queue(const char *label, struct crypt_queue *queue);
void print_wg_device(struct wg_device *device);
void print_skbuff_head_info(const char *label, struct sk_buff_head *queue);
void print_tcp_socket_info(struct socket *sock, const char *label);
void print_peer_socket_info(struct wg_peer *peer);

#ifdef WG_TCP_DIAG
extern atomic64_t wg_tcp_stats_tx_bytes;
extern atomic64_t wg_tcp_stats_rx_bytes;
extern atomic64_t wg_tcp_stats_tx_packets;
extern atomic64_t wg_tcp_stats_rx_packets;
extern atomic64_t wg_tcp_stats_tx_eagain;
extern atomic64_t wg_tcp_stats_tx_errors;
extern atomic64_t wg_tcp_stats_rx_errors;
extern atomic64_t wg_tcp_stats_short_writes;
extern atomic64_t wg_tcp_stats_retransmits;

void wg_tcp_diag_dump_sock(struct sock *sk, const char *where,
			   int result, unsigned int queued);
void wg_tcp_diag_pressure(struct sock *sk, u64 peer_id);
void wg_tcp_diag_aggregate(void);
#endif

#endif /* _WG_TCP_DEBUG_H */
