#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from bcc import BPF
from time import sleep
from stat import *

b = BPF(src_file='./file_mon.c')
b.attach_kprobe(event='vfs_read',fn_name='read_mon')
b.attach_kprobe(event='vfs_readv',fn_name='readv_mon')
b.attach_kprobe(event='vfs_write',fn_name='write_mon')
b.attach_kprobe(event='vfs_writev',fn_name='writev_mon')


TIMER = 1000
print("Analysing...\nMAX 1000s\nCtrl-C to stop counting")
try:
    sleep(TIMER)
except KeyboardInterrupt:
    pass

table = b.get_table('table')

print("\n%-10s %-20s %-25s %15s:%-15s %15s:%-15s" %("PID","NAME","TYPE","READ","NUM","WRITE","NUM"))

for i in table.items():
    key = i[0]
    val = i[1]
    pid = key.pid
    name = key.name
    mode = key.type
    read = val.read_cnt
    write = val.write_cnt
    if S_ISDIR(mode):
        mode = "directory"
    elif S_ISCHR(mode):
        mode = "character special dev"
    elif S_ISBLK(mode):
        mode = "block special dev"
    elif S_ISREG(mode):
        mode = "regular file"
    elif S_ISFIFO(mode):
        mode = "FIFO"
    elif S_ISLNK(mode):
        mode = "symbolic link"
    elif S_ISSOCK(mode):
        mode = "socket"
    elif S_ISDOOR(mode):
        mode = "door"
    elif S_ISPORT(mode):
        mode = "event port"
    elif S_ISWHT(mode):
        mode = "whiteout"
    else:
        continue
    
    print("\n%-10d %-20s %-25s %15s:%-15s %15s:%-15s" %(pid,name,mode,"READ",read,"WRITE",write))
    

