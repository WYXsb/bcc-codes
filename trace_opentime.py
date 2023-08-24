# 
import sys
import os
import datetime
import time
import ctypes
from ctypes import *
import psutil
from pprint import pprint
from bcc import BPF

b = BPF(src_file = "trace_opentime.c")
rootpath = os.getcwd() + "/file"
path = "./file"


print("rootpath:" + rootpath)
# localtime = time.localtime()
starttime = datetime.datetime.now()
print(type(starttime))
print("Now:" + starttime.strftime("%Y-%m-%d %H:%M:%S"))
# l = localtime.split()

time_array = b.get_table("time_array")
class BeijingTime(Structure):
    _fields_ = [(
            ("boottime",c_ulonglong))]
boot_time = psutil.boot_time()
boot_datetime = datetime.datetime.fromtimestamp(boot_time)
print(type(boot_datetime))
localtime = [c_ulonglong(int(psutil.boot_time()))]
beijingTime = BeijingTime(*localtime)
time_array[ctypes.c_int(0)] = beijingTime           

def callback(ctx, data, size):
    global boot_datetime
    event = b['buffer'].event(data)
    if path == event.filename.decode('utf-8') or rootpath == event.filename.decode('utf-8'):
        opentime = boot_datetime +datetime.timedelta(seconds= (event.opentime) / 1000000000)
        print("%-64s %10d %10d %10d %24s" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,opentime.strftime("%Y-%m-%d %H:%M:%S")))
        # print("%-64s %10d %10d %10d %24d" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode,opentime.strftime("%Y-%m-%d %H:%M:%S")))
    

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