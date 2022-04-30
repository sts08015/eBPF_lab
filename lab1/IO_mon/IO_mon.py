from bcc import BPF
from time import sleep

REQ_WRITE = 1

b = BPF(src_file="./IO_mon.c")

b.attach_kprobe(event="blk_mq_start_request", fn_name="IO_mon")

TIMER = 1000
print("Analysing...\nMAX 1000s\nCtrl-C to stop counting")

try:
    sleep(TIMER)
except KeyboardInterrupt:
    pass

table = b.get_table('table')
print("\n%-10s %5s %5s %5s %5s" % ("DEV", "RS", "RR", "WS","WR"))

for i in table.items():
    key = i[0]
    val = i[1]
    print("\n%-10s %5d %5d %5d %5d" % (key.name, val.read_seq_cnt, val.read_rand_cnt, val.write_seq_cnt,val.write_rand_cnt))
