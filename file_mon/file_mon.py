#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
from bcc import BPF
from time import sleep

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

table = b.get_table('arr')

