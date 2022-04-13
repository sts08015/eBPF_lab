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


def print_event(cpu, data, size):
    event = b["events"].event(data)
    #print(event.name.decode('utf-8', 'replace'))

