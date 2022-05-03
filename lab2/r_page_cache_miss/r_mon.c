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
    u16 read;
    u16 ext4;
    u16 pcache;
    u16 plug_start;
    u16 plug_fin;
    u16 sched_start;
    u16 sched_fin;
    u16 nvme_start;
    u16 nvme_fin;
};

struct f_order{
    char f_name[FUNC_NAME_LEN];
    u16 order;
};

struct timeval {
    double time;    //microsecs
};

BPF_HASH(events,struct key_t, struct call_num);

BPF_HASH(inner, struct f_order, struct timeval);
BPF_HASH_OF_MAPS(root, struct key_t, "inner", 10);

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

size_t r_start(struct pt_regs *ctx,int fd, void *buf, size_t count)
{
    char comm[PROG_NAME_LEN] ={0};
    struct key_t k = {0};

    //check process name
    int ret = chk_comm(comm,&comm,sizeof(comm));
    if(ret!=0) return -1;

    //check pid
    k.pid = bpf_get_current_pid_tgid()&0xffffffff;

    struct call_num num = {0};
    num.read = 1;
    
    events.update(&k,&num);
    return 0;
}

ssize_t ext4_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    struct key_t k = {0};

    //check target file name
    int ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;
    
    //check read op
    ret = chk_op(to);
    if(ret!=0) return -1;

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;

    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        ++(tmp->ext4);
        bpf_trace_printk("fis_ext %u\n",k.pid);
        bpf_trace_printk("fis_ext cnt : %u\n",to->count);
        bpf_trace_printk("fis_ext len : %u\n",to->iov->iov_len);
    }
    else return -1;

    return 0;
}

int pagecache_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,struct pagevec *pvec)
{
    struct key_t k = {0};

    //check target file name
    int ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;

    //check read op
    ret = chk_op(iter);
    if(ret!=0) return -1;

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_pcache %u\n",k.pid);
        ++(tmp->pcache);
    } 
    else return -1;

    return 0;
}

void plug_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_plug %u\n",k.pid);
        ++(tmp->plug_start);
    }
    else return;
}

void plugfin_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_plug_fin %u\n",k.pid);
        ++(tmp->plug_fin);
    }
    else return;
}

void io_start(struct pt_regs *ctx)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_sched_start %u\n",k.pid);
        ++(tmp->sched_start);
    }
    else return;
}

void ret_io(struct pt_regs *ctx)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_sched_fin %u\n",k.pid);
        ++(tmp->sched_fin);
    }
    else return;
}

void nvme_start(struct pt_regs *ctx,struct nvme_queue *nvmeq, struct nvme_command *cmd,bool write_sq)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_nvme_start %u\n",k.pid);
        ++(tmp->nvme_start);
    }
    else return;
}

void ret_nvme(struct pt_regs *ctx,struct nvme_queue *nvmeq, struct nvme_command *cmd,bool write_sq)
{
    struct key_t k = {0};

    k.pid = bpf_get_current_pid_tgid()&0xffffffff;
    struct call_num* tmp = events.lookup(&k);
    if(tmp){
        bpf_trace_printk("fis_nvme_fin %u\n",k.pid);
        ++(tmp->nvme_fin);
    }
    else return;
}
/*
*/