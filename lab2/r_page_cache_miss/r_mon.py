from bcc import BPF
import operator

b = BPF(src_file='./r_mon.c')

#track read syscall
read_fnname = b.get_syscall_fnname('read')
b.attach_kprobe(event=read_fnname,fn_name='r_start')

#track ext4 file read
b.attach_kprobe(event='ext4_file_read_iter',fn_name="ext4_start")

#track page cache interaction
b.attach_kprobe(event='filemap_get_pages',fn_name='pagecache_start')

#track plugging
b.attach_kprobe(event='blk_start_plug',fn_name='plug_start')
b.attach_kprobe(event='blk_finish_plug',fn_name='plugfin_start')

#track context switching
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io')

#track nvme driver
b.attach_kprobe(event='nvme_submit_cmd',fn_name='nvme_start')
b.attach_kretprobe(event='nvme_submit_cmd',fn_name='ret_nvme')
'''
'''

def print_timeline(s):
    print("TIMELINE")
    arr = {}
    arr["read start"]                   = s.rst
    #arr["read end"]                     = s.ret
    arr["ext4_file_read_iter start"]    = s.est
    #arr["ext4_file_read_iter end"]      = s.eet
    arr["filemap_get_pages start"]      = s.pst
    #arr["filemap_get_pages end"]        = s.pet
    #arr["blk_start_plug start"]         = s.bsst
    #arr["blk_start_plug end"]           = s.bset
    #arr["blk_finish_plug start"]        = s.bfst
    #arr["blk_finish_plug end"]          = s.bfet
    #arr["context switch start"]         = s.sst
    #arr["context switch end"]           = s.set
    #arr["nvme_submit_cmd start"]        = s.nst
    #arr["nvme_submit_cmd end"]          = s.net

    offset = s.rst
    arr = sorted(arr.items(),key=operator.itemgetter(1))
    for k,v in arr:
        print("%-20s : %f"%(k,(v-offset)/1000))


def print_info(obj):
    pid = obj[0].pid
    val = obj[1]
    
    if val.ext4 == 0:
        return
    
    print('%-12s : %5u ' %("PID",pid))
    print("=== CALL_NUM ===")
    print("%-12s : %5d" %("read",val.read))
    print("%-12s : %5d" %("ext4",val.ext4))
    print("%-12s : %5d" %("pcache",val.pcache))
    print("%-12s : %5d" %("plug_start",val.plug_start))
    print("%-12s : %5d" %("plug_fin",val.plug_fin))
    print("%-12s : %5d" %("sched_start",val.sched_start))
    print("%-12s : %5d" %("sched_fin",val.sched_fin))
    print("%-12s : %5d" %("nvme_start",val.nvme_fin))
    print("%-12s : %5d" %("nvme_fin",val.nvme_fin))
    print('')


print('Press Ctrl-C after IO is over')
while True:
    try:
        pass
    except KeyboardInterrupt:
        print("")
        break

event = b.get_table('events')
#timeval = b.get_table('times')

for i in event.items():
    print_info(i)

#tmp = timeval.items()[0]
#print_timeline(tmp[1])