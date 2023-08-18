#/usr/bin/python3
# Trace_print just read from file /sys/kernel/debug/tracing/trace_pipe and print its content
# fmt split the whloe string into args .
# Using fmt , we can get args that we need to be printed.
# But it's a debug facility.
from bcc import BPF

prog = """
int kprobe__sys_clone(void *ctx) 
{ 
    bpf_trace_printk("Hello, World!\\n"); 
    return 0; 
    }
"""
b = BPF(text = prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="kprobe__sys_clone")

print("PID MESSAGE")

try:
    b.trace_print()
    #b.trace_print(fmt = "{1} {2} {3} {4} {5}")
    # blocking
except KeyboardInterrupt:
    print("bye")
    exit()