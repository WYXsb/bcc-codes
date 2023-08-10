import sys
import time

from bcc import BPF

src = r"""
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {
    char filename[16];
    int dfd;
    int flags;
    int mode;
    int pid;
    int pname;
};

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;

    struct event event = {};

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);


    event.dfd = args->dfd;
    event.flags = args->flags;
    event.mode = args->mode;

    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
"""

b = BPF(text=src)
s =  "/proc/stat"
t = 0
def callback(ctx, data, size):
    global t
    event = b['buffer'].event(data)
    if s == event.filename.decode('utf-8'):
        t = t + 1
        print("%-16s %10d %10d %10d %d" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,t))
    
    

b['buffer'].open_ring_buffer(callback)

print("Printing openat() calls, ctrl-c to exit.")

print("%-16s %10s %10s %10s %10s" % ("FILENAME", "DIR_FD", "FLAGS", "MODE", "OPENTIME"))

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()