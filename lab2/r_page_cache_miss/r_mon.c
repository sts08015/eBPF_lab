#include <uapi/linux/ptrace.h>
#include <linux/nvme.h>
#include <linux/pci.h>
#include <asm/types.h>
#include <linux/fs.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

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
    u32 pos;
};

struct ext4_val{
    u64 time;
    volatile u32 cnt;
};

struct filemap_key{
    u32 pos;
};

struct filemap_val{
    u64 time;
    volatile u32 cnt;
};

struct bio_key{
    u32 hmm;
};

struct bio_val{
    u64 time;
    volatile u32 cnt;
};

BPF_HASH(events,struct key_t, struct call_num);
BPF_HASH(read_map,struct read_key, struct read_val);
BPF_HASH(ext4_map,struct ext4_key, struct ext4_val);
BPF_HASH(filemap_map,struct filemap_key, struct filemap_val);
BPF_HASH(bio_map,struct bio_key, struct bio_val);

static const char * fio = "fio";
static const char * target = "test";

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
        //bpf_trace_printk("fis_ext %u\n",k.pid);
        //bpf_trace_printk("fis_ext_pos %u\n",iocb->ki_pos);
    }
    else return -1;

    struct ext4_key ek = {0};
    struct ext4_val ev = {0};
    ek.pos = iocb->ki_pos;
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
    fv.time = t;
    
    struct ext4_key ek = {0};
    ek.pos = fk.pos;
    struct ext4_val* tmp2 = ext4_map.lookup(&ek);
    if(tmp2) ++(tmp2->cnt);
    else return -1;

    filemap_map.insert(&fk,&fv);
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
    bpf_trace_printk("bio_s %llu\n",t);


    
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
    bpf_trace_printk("sched_s %llu\n",t);

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
    bpf_trace_printk("sched_f %llu\n",t);
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
    bpf_trace_printk("nvme_s %llu\n",t);
    
}