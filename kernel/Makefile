ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-y += -I$(src)/../include -I$(src)/../include/uapi
ccflags-y += -include $(src)/wireguard_tcp_uapi.h
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG

# WireGuard TCP debug levels (add to EXTRA_CFLAGS or uncomment here):
#   -DWG_TCP_VERBOSE    Function enter/exit traces, param dumps (very noisy)
#   -DWG_TCP_DIAG       TCP performance diagnostics (cwnd, rtt, retrans)
#   Neither              No debug output (production)
# Example: make ... EXTRA_CFLAGS="-DWG_TCP_DIAG"
# ccflags-y += -DWG_TCP_VERBOSE -DWG_TCP_DIAG
wireguard-y := main.o
wireguard-y += noise.o
wireguard-y += device.o
wireguard-y += peer.o
wireguard-y += timers.o
wireguard-y += queueing.o
wireguard-y += send.o
wireguard-y += receive.o
wireguard-y += socket.o
wireguard-y += wg_tcp.o
wireguard-y += peerlookup.o
wireguard-y += allowedips.o
wireguard-y += ratelimiter.o
wireguard-y += cookie.o
wireguard-y += netlink.o
obj-$(CONFIG_WIREGUARD) := wireguard.o
