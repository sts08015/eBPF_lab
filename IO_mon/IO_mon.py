#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
from bcc import BPF
from time import sleep

b = BPF(src_file='./IO_mon.c')
b.attach_kprobe(event='blk_mq_start_request',fn_name='track_IO')

TIMER = 1000
print("Analysing...\nMAX 1000s\nCtrl-C to stop counting")
try:
    sleep(TIMER)
except KeyboardInterrupt:
    pass

table = b.get_table('arr')
