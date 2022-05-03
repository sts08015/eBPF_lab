from bcc import BPF
import operator

b = BPF(src_file='./r_mon.c')

#track read syscall
read_fnname = b.get_syscall_fnname('read')
b.attach_kprobe(event=read_fnname,fn_name='r_start')

#track ext4 file read
b.attach_kprobe(event='ext4_file_read_iter',fn_name="ext4_start")

#track page cache interaction
b.attach_kprobe(event='filemap_read',fn_name='pagecache_start')

#track plugging
b.attach_kprobe(event='blk_start_plug',fn_name='plug_start')
b.attach_kprobe(event='blk_finish_plug',fn_name='plugfin_start')

#track context switching
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io')

#track nvme driver
b.attach_kprobe(event='nvme_submit_cmd',fn_name='nvme_start')
b.attach_kretprobe(event='nvme_submit_cmd',fn_name='ret_nvme')


def breakdown():
    read_map = b.get_table('read_map')
    ext4_map = b.get_table('ext4_map')

    for i in read_map.items():
        rv = i[1]
        if rv.cnt == 0:
            continue
        offset = rv.time/1000
        #print(offset)
        print('read -> ext4 branch num : %d' %(rv.cnt))
        aretime = 0
        for i1 in ext4_map.items():
            ev = i1[1]
            #print(ev.time/1000)
            aretime+=(ev.time/1000-offset)

        print('read -> ext4 avg time : %f' %(aretime/rv.cnt))


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

breakdown()