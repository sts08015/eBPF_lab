from bcc import BPF
import sys
import operator


f_name = ['read','ext4_file_read_iter','filemap_read','submit_bio','nvme_submit_cmd','io_schedule']

def usage():
    print('\nsudo ./r_mon.py <func1> <func2>')
    print("give name of two different functions you want to check #of branches and avg time\n")
    print("LIST OF FUNCTION NAME")
    for i in range(len(f_name)):
        print("%d.   %s" %(i,f_name[i]))
    exit(1)


if len(sys.argv) != 3:
    usage()
elif (sys.argv[1] not in f_name) or (sys.argv[2] not in f_name) or sys.argv[1] == sys.argv[2]:
    usage()

b = BPF(src_file='./r_mon.c')

#track read syscall
read_fnname = b.get_syscall_fnname('read')
b.attach_kprobe(event=read_fnname,fn_name='r_start')

#track ext4 file read
b.attach_kprobe(event='ext4_file_read_iter',fn_name="ext4_start")

#track page cache interaction
b.attach_kprobe(event='filemap_read',fn_name='filemap_start')

#track block io
b.attach_kprobe(event='submit_bio',fn_name='bio_start')

#track nvme driver
b.attach_kprobe(event='nvme_submit_cmd',fn_name='nvme_start')

#track context switching
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io')

def breakdown():

    maps = []
    maps.append(b.get_table('read_map'))
    maps.append(b.get_table('ext4_map'))
    maps.append(b.get_table('filemap_map'))
    maps.append(b.get_table('bio_map'))
    
    idx1 = f_name.index(sys.argv[1])
    idx2 = f_name.index(sys.argv[2])
    f_name1 = ""
    f_name2 = ""

    if idx1 < idx2:
        f_name1 = sys.argv[1]
        f_name2 = sys.argv[2]
    else:
        f_name1 = sys.argv[2]
        f_name2 = sys.argv[1]
        tmp = idx1
        idx1 = idx2
        idx2 = tmp

    map1 = maps[idx1].items()
    map2 = maps[idx2].items()

    branch_dict = {}
    time_vals = []

    cur = 0
    for i in map1:
        val = i[1]
        
        if val.cnt == 0:
            continue

        if val.cnt in branch_dict:
            branch_dict[val.cnt]+=1
        else:
            branch_dict[val.cnt] = 1
        
        print(val.cnt)
        print(len(map2))
        st = (val.time/1000)
        tt = 0
        for j in range(cur,cur+val.cnt):
            val2 = map2[j][1]
            tt += ((val2.time/1000)-st)
        
        #print(val.cnt)
        time_vals.append((tt/val.cnt))
        cur+=val.cnt

    for k,v in branch_dict.items():
        print("%s -> %s branch : %d x %d" %(f_name1,f_name2,k,v))

    at = 0
    for i in time_vals:
        at+=i
    
    if len(time_vals)!=0:
        at /= len(time_vals)
    print('avg of avg time : %f' %(at))

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
    print("%-12s : %5d" %("bio_start",val.bio_start))
    print("%-12s : %5d" %("nvme_start",val.nvme_start))
    print("%-12s : %5d" %("sched_start",val.sched_start))
    print("%-12s : %5d" %("sched_fin",val.sched_fin))
    print('')


print('Press Ctrl-C after IO is over')
while True:
    try:
        pass
    except KeyboardInterrupt:
        print("")
        break

event = b.get_table('events')

for i in event.items():
    print_info(i)

breakdown()