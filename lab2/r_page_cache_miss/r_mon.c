#include <uapi/linux/ptrace.h>
#include <linux/pci.h>
#include <asm/types.h>
#include <linux/fs.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include "./linux-5.13/drivers/nvme/host/nvme.h"
#include "nvme_related.h"

#define PROG_NAME_LEN 16
#define FUNC_NAME_LEN 16

struct key_t{
    u32 pid;
};

struct call_num{
    volatile u32 read;
    volatile u32 ext4;
    volatile u32 pcache;
    volatile u32 bio_start;
    volatile u32 sched_start;
    volatile u32 sched_fin;
    volatile u32 nvme_start;
};

struct read_key{
    u32 pid;
};

struct read_val{
    u64 time;
    volatile u32 cnt;
};

struct ext4_key{
    u32 pid;
    u32 pos;
};

struct ext4_val{
    u64 time;
    volatile u32 cnt;
};

struct filemap_key{
    u32 pid;
    u32 pos;
};

struct filemap_val{
    u64 time;
    u64 len;
    volatile u32 cnt;
};

struct bio_key{
    u32 pid;
    u32 hmm;
};

struct bio_val{
    u64 time;
    volatile u32 cnt;
};

BPF_HASH(events,struct key_t, struct call_num,300000);
BPF_HASH(read_map,struct read_key, struct read_val,300000);
BPF_HASH(ext4_map,struct ext4_key, struct ext4_val,300000);
BPF_HASH(filemap_map,struct filemap_key, struct filemap_val,300000);
BPF_QUEUE(queue,struct filemap_key,300000);

BPF_HASH(bio_map,struct bio_key, struct bio_val,300000);


static const char * fio = "fio";
static const char * target = "test";
static const char * dev = "nvme0n1";

static int str_cmp(const char *a,const char *b, int len)
{
    int i;
    for(i=0;i<len;i++)
    {
        if(a[i]!=b[i]) return -1;
    }
    return 0;
}

static int chk_comm(char* buf,void* tmp,int size)
{
    bpf_get_current_comm(tmp,size);
    return str_cmp(buf,fio,3);
}

static void get_name(char* buf,struct file* f, u64 size)
{
    struct dentry* dent = (f->f_path).dentry;
    struct qstr d_name = dent->d_name;
    bpf_probe_read_kernel(buf,size-1,d_name.name);
}

static int chk_file(struct file * f)
{
    char buf[TASK_COMM_LEN];
    get_name(buf,f,TASK_COMM_LEN);
    
    int ret = str_cmp(buf,target,4);
    return ret;
}

static int chk_op(struct iov_iter *to)
{
    u32 tmp = to->type;
    return (tmp&1);
}

static int chk_disk(struct bio* bio)
{
    const char* disk_name = bio->bi_bdev->bd_disk->disk_name;
    char disk[DISK_NAME_LEN] = {0};
    bpf_probe_read_kernel_str(disk,DISK_NAME_LEN,disk_name);
    return str_cmp(dev,disk,7);
}

size_t r_start(struct pt_regs *ctx, int fd, void *buf, size_t count)
{
    u64 t = bpf_ktime_get_ns();
    char comm[PROG_NAME_LEN] ={0};
    struct key_t k = {0};

    //check process name
    int ret = chk_comm(comm,&comm,sizeof(comm));
    if(ret!=0) return -1;

    //check pid
    k.pid = bpf_get_current_pid_tgid();

    struct call_num num = {0};
    num.read = 1;
    events.insert(&k,&num);

    struct read_key rk = {0};
    struct read_val rv = {0};
    rk.pid = k.pid;
    rv.time = t;
    read_map.insert(&rk,&rv);

    return 0;
}

ssize_t ext4_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    u64 t = bpf_ktime_get_ns();
    struct key_t k = {0};

    //check target file name
    int ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;
    
    //check read op
    ret = chk_op(to);
    if(ret!=0) return -1;

    k.pid = bpf_get_current_pid_tgid();

    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        ++(tmp->ext4);
        //bpf_trace_printk("fis_ext_pos %u\n",iocb->ki_pos);
    }
    else return -1;

    struct ext4_key ek = {0};
    struct ext4_val ev = {0};
    ek.pos = iocb->ki_pos;
    ek.pid = k.pid;
    ev.time = t;

    struct read_key rk = {0};
    rk.pid = k.pid;
    struct read_val* tmp2 = read_map.lookup(&rk);
    if(tmp2) ++(tmp2->cnt);
    else return -1;

    ext4_map.insert(&ek,&ev);
    
    return 0;
}

int filemap_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,ssize_t already_read)
{
    u64 t = bpf_ktime_get_ns();
    struct key_t k = {0};

    //check target file name
    int ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;

    //check read op
    ret = chk_op(iter);
    if(ret!=0) return -1;

    k.pid = bpf_get_current_pid_tgid();
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        //bpf_trace_printk("fis_pcache_pos %u\n",iocb->ki_pos);
        ++(tmp->pcache);
    } 
    else return -1;

    struct filemap_key fk = {0};
    struct filemap_val fv = {0};
    fk.pos = iocb->ki_pos;
    fk.pid = k.pid;
    fv.len = iter->bvec->bv_len;
    fv.time = t;
    
    struct ext4_key ek = {0};
    ek.pos = fk.pos;
    ek.pid = k.pid;

    struct ext4_val* tmp2 = ext4_map.lookup(&ek);
    if(tmp2) ++(tmp2->cnt);
    else return -1;

    filemap_map.insert(&fk,&fv);
    bpf_trace_printk("fileread_dbg_len %u\n",iter->bvec->bv_len);
    bpf_trace_printk("fileread_dbg_offset %u\n",iter->bvec->bv_offset);
    bpf_trace_printk("fileread_dbg_alread %u\n",already_read);

    queue.push(&fk,BPF_EXIST);

    return 0;
}

void bio_start(struct pt_regs *ctx,struct bio *bio)
{
    u64 t = bpf_ktime_get_ns();

    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid();
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        //bpf_trace_printk("fis_plug %u\n",k.pid);
        ++(tmp->bio_start);
    }
    else return;

    //check target disk name
    int ret = chk_disk(bio);
    if(ret!=0) return;
    bpf_trace_printk("bio_dbg_size %u\n",(bio->bi_iter).bi_size);
    bpf_trace_printk("bio_dbg_vcnt %u\n",bio->bi_vcnt);
    bpf_trace_printk("bio_dbg_cnt %u\n",bio->__bi_cnt);

    struct filemap_key fk = {0};
    ret = queue.pop(&fk);
    bpf_trace_printk("bio_dbg_que %u\n",ret);
    if(ret != 0) return;

    struct filemap_val* tmp2 = filemap_map.lookup(&fk);
    if(tmp2){
        int set = (tmp2->len)/((bio->bi_iter).bi_size);
        bpf_trace_printk("bio_dbg_set %u\n",set);
        (tmp2->cnt) += set;
    }
    else return;
    
    struct bio_key bk = {0};
    struct bio_val bv = {0};
    bk.pid = k.pid;
    //NOT FINISHED WITH KEY SELECTION!
    bv.time = t;

    bio_map.insert(&bk,&bv);
}

void nvme_start(struct pt_regs *ctx,struct nvme_queue *nvmeq, struct nvme_command *cmd, bool write_sq)
{
    u64 t = bpf_ktime_get_ns();
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid();
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        //bpf_trace_printk("fis_nvme_start %u\n",k.pid);
        ++(tmp->nvme_start);
    }
    else return;
    
    bpf_trace_printk("nvme_ts %llu\n",t);
    bpf_trace_printk("nvme_dbg %d\n",write_sq);
    
}

void io_start(struct pt_regs *ctx)
{
    u64 t = bpf_ktime_get_ns();
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid();
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        //bpf_trace_printk("fis_sched_start %u\n",k.pid);
        ++(tmp->sched_start);
    }
    else return;
    bpf_trace_printk("sched_ts %llu\n",t);

}

void ret_io(struct pt_regs *ctx)
{
    u64 t = bpf_ktime_get_ns();
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid();
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        //bpf_trace_printk("fis_sched_fin %u\n",k.pid);
        ++(tmp->sched_fin);
    }
    else return;
    bpf_trace_printk("sched_f_ts %llu\n",t);
}