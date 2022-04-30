from bcc import BPF

b = BPF(src_file='./r_mon.c')

#track read syscall
read_fnname = b.get_syscall_fnname('read')
b.attach_kprobe(event=read_fnname,fn_name='r_start')
b.attach_kretprobe(event=read_fnname,fn_name='ret_r')

#track ext4 file read
b.attach_kprobe(event='ext4_file_read_iter',fn_name="ext4_start")
b.attach_kretprobe(event='ext4_file_read_iter',fn_name="ret_ext4")

#track page cache interaction
b.attach_kprobe(event='filemap_get_pages',fn_name='pagecache_start')
b.attach_kretprobe(event='filemap_get_pages',fn_name='ret_pagecache')

#track plugging
b.attach_kprobe(event='blk_start_plug',fn_name='plug_start')
b.attach_kretprobe(event='blk_start_plug',fn_name='ret_plug')
b.attach_kprobe(event='blk_finish_plug',fn_name='plugfin_start')
b.attach_kretprobe(event='blk_finish_plug',fn_name='ret_plugfin')

#track context switching
b.attach_kprobe(event='io_schedule',fn_name='io_start')
b.attach_kretprobe(event='io_schedule',fn_name='ret_io')

print('hello')