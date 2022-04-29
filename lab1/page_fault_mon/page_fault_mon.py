#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
from __future__ import print_function
from bcc import BPF
from time import sleep

b = BPF(src_file='./page_fault_mon.c')
b.attach_kprobe(event='handle_mm_fault',fn_name='fault_counter')

print("Counting Page Faults...\nMAX 1000s\nCtrl-C to stop counting")
TIMER = 1000
try:
    sleep(TIMER)
except KeyboardInterrupt:
    pass

print("%-20s %-10s" %("\nNAME", "COUNT"))
table = b.get_table('table')

for i in table.items():
    print("%-20s %-10d" %(i[0].name,i[1].value))
