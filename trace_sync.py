#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#define TASK_COMM_LEN 16
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);
BPF_HASH(last);

struct data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    u64 lasttime;
};
int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    struct data_t data = {};
    // attempt to read stored timestamp
    bpf_trace_printk("Hello, World!\\n"); 
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        data.pid = bpf_get_current_pid_tgid();
        data.uid = bpf_get_current_uid_gid();
        data.gid = bpf_get_current_uid_gid() >> 32;
        data.lasttime = delta;
        // output if time is less than 1 second
        bpf_trace_printk("%d\\n", delta / 1000000);
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    except KeyboardInterrupt:
        exit()