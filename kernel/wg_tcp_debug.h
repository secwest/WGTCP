/* SPDX-License-Identifier: GPL-2.0 */
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

#endif /* _WG_TCP_DEBUG_H */
