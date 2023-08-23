# 
import sys
import os
import time
import ctypes
from ctypes import *
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
        print("%-64s %10d %10d %10d %s" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,time.strftime('%a %b %d %H:%M:%S %Y', time.localtime())))
    # print("%-64s %10d %10d %10d %24d" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,event.lasttime))
    

b['buffer'].open_ring_buffer(callback)
time_array = b.get_table("time_array")

localtime = time.strftime('%Y %m %d %H %M %S', time.localtime())
l = localtime.split()

class BeijingTime(Structure):
    _fields_ = [("year", c_int),
            ("month", c_int),
            ("day", c_int),
            ("hour", c_int),
            ("minute", c_int),
            ("second", c_int)]
            
localtime = [c_int(int(l[0])),c_int(int(l[1])),c_int(int(l[2])),c_int(int(l[3])),c_int(int(l[4])),c_int(int(l[5]))]
print(localtime)
beijingTime = BeijingTime(*localtime)
time_array[ctypes.c_int(0)] = beijingTime
print("Printing openat() calls, ctrl-c to exit.")

print("%-64s %10s %10s %10s %24s" % ("FILENAME", "DIR_FD", "FLAGS", "MODE", "OPENTIME"))

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()