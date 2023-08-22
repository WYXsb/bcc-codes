# 
import sys
import os
import time
from bcc import BPF

b = BPF(src_file = "trace_opentime.c")
rootpath = os.getcwd() + "/file"
path = "./file"
# rootpath = "/home/wyx/workspace/bcc-codes/file"
# times = 0
print(rootpath)

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    if path == event.filename.decode('utf-8') or rootpath == event.filename.decode('utf-8'):
    # print("%-64s %10d %10d %10d %s" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,time.strftime('%a %b %d %H:%M:%S %Y', time.localtime())
        print("%-64s %10d %10d %10d %24d" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,event.lasttime))
    

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