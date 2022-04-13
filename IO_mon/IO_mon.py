#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
from bcc import BPF

b = BPF(src_file='./sched_out_mon.c')
b.attach_kprobe(event='blk_mq_start_request',fn_name='io_mon')


def print_event(cpu, data, size):
    event = b["events"].event(data)

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
