from bcc import BPF
import operator

b = BPF(src_file='./r_mon.c')

#track read syscall
read_fnname = b.get_syscall_fnname('read')
b.attach_kprobe(event=read_fnname,fn_name='r_start')
b.attach_kretprobe(event=read_fnname,fn_name='ret_r')

#track ext4 file read
b.attach_kprobe(event='ext4_file_read_iter',fn_name="ext4_start")
#b.attach_kretprobe(event='ext4_file_read_iter',fn_name="ret_ext4")

#track page cache interaction
b.attach_kprobe(event='filemap_get_pages',fn_name='pagecache_start')
#b.attach_kretprobe(event='filemap_get_pages',fn_name='ret_pagecache')

#track plugging
b.attach_kprobe(event='blk_start_plug',fn_name='plug_start')
#b.attach_kretprobe(event='blk_start_plug',fn_name='ret_plug')
b.attach_kprobe(event='blk_finish_plug',fn_name='plugfin_start')
#b.attach_kretprobe(event='blk_finish_plug',fn_name='ret_plugfin')

#track context switching
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io')

#track nvme driver
b.attach_kprobe(event='nvme_submit_cmd',fn_name='nvme_start')
b.attach_kretprobe(event='nvme_submit_cmd',fn_name='ret_nvme')

def print_timeline(s):
    print("TIMELINE")
    arr = {}
    arr["read start"]                   = s.rst
    arr["read end"]                     = s.ret
    arr["ext4_file_read_iter start"]    = s.est
    #arr["ext4_file_read_iter end"]      = s.eet
    arr["filemap_get_pages start"]      = s.pst
    #arr["filemap_get_pages end"]        = s.pet
    arr["blk_start_plug start"]         = s.bsst
    #arr["blk_start_plug end"]           = s.bset
    arr["blk_finish_plug start"]        = s.bfst
    #arr["blk_finish_plug end"]          = s.bfet
    arr["context switch start"]         = s.sst
    arr["context switch end"]           = s.set
    arr["nvme_submit_cmd start"]        = s.nst
    arr["nvme_submit_cmd end"]          = s.net

    offset = s.rst
    arr = sorted(arr.items(),key=operator.itemgetter(1))
    for k,v in arr:
        print("%-20s : %f"%(k,(v-offset)/1000))



print('Press Ctrl-C after IO is over')
while True:
    try:
        pass
    except KeyboardInterrupt:
         break

event = b.get_table('events')
timeval = b.get_table('times')

for i in event.items():
    key = i[0].comm.decode('utf-8','replace')
    val = i[1].value
    print('\nNAME : %s'%(key))
    print('TOTAL IO : %d\n\n'%(val))

tmp = timeval.items()[0]
print_timeline(tmp[1])