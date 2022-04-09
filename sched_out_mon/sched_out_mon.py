#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime


b = BPF(src_file='./sched_out_mon.c')
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io_sched')


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-6d %-16s %-7.2f" % (event.pid,event.comm.decode('utf-8', 'replace'), float(event.delta)))

print("%-6s %-16s %-7s" % ("PID", "COMM", "DELTA(ns)"))
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
