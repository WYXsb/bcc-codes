#!/usr/bin/python
#
# tcpv4connect	Trace TCP IPv4 connect()s.


from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import time
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#define TASK_COMM_LEN 16

BPF_RINGBUF_OUTPUT(buffer, 1 << 4);
BPF_HASH(currsock, u32, struct sock *);

struct event {
    u32 dport;
    u32 saddr;
    u32 daddr;
    u32 pid;
    char comm[TASK_COMM_LEN];
};
int do_trace(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);

	return 0;
}

int do_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
    struct event event= {};
	
	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
    event.saddr = saddr;
    event.daddr = daddr;
    event.dport = dport;
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
	// output
	buffer.ringbuf_output(&event, sizeof(event), 0);
	//bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

	currsock.delete(&pid);

	return 0;
}
"""
def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print("%-6d %-12.12s %-16s %-16s %-4s" % (event.pid, event.comm.decode('utf-8'),inet_ntoa(event.saddr),inet_ntoa(event.daddr),event.dport))

# initialize BPF
b = BPF(text=bpf_text)
b['buffer'].open_ring_buffer(callback)
b.attach_kprobe(event="tcp_v4_connect", fn_name="do_trace")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="do_return")
# header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

# # filter and format output
# while 1:
# 	# Read messages from kernel pipe
# 	try:
# 	    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
# 	    (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
# 	except ValueError:
# 	    # Ignore messages from other tracers
# 	    continue
# 	except KeyboardInterrupt:
# 	    exit()

# 	# Ignore messages from other tracers

# 	printb(b"%-6d %-12.12s %-16s %-16s %-4s" % (pid, task,
# 	    inet_ntoa(int(saddr_hs, 16)),
# 	    inet_ntoa(int(daddr_hs, 16)),
# 	    dport_s))
try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    exit()