import sys
import time

from bcc import BPF

src = """
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {
    char filename[64];
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
path =  "./file"
rootpath = "/home/wyx/workspace/bcc-codes/file"
# times = 0

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    if path == event.filename.decode('utf-8') or rootpath == event.filename.decode('utf-8'):
        print("%-64s %10d %10d %10d %s" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,time.strftime('%a %b %d %H:%M:%S %Y', time.localtime())
))
    
    

b['buffer'].open_ring_buffer(callback)

print("Printing openat() calls, ctrl-c to exit.")

print("%-64s %10s %10s %10s %24s" % ("FILENAME", "DIR_FD", "FLAGS", "MODE", "OPENTIME"))

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()