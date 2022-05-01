#include <uapi/linux/ptrace.h>
#include <linux/nvme.h>
#include <asm/types.h>
#include <linux/fs.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

#define PROG_NAME_LEN 16

struct data_t
{
    char comm[PROG_NAME_LEN];
};

struct key_data_t
{
    u32 pid;
};

struct timeval {
    u64 rst;
    u64 ret;

    u64 est;
    u64 eet;

    u64 pst;
    u64 pet;

    u64 bsst;
    u64 bset;

    u64 bfst;
    u64 bfet;

    u64 sst;
    u64 set;
};

BPF_HASH(times,struct key_data_t,struct timeval);
BPF_HASH(events,struct data_t);

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
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;

    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    struct timeval time = {0};
    u64 ts = bpf_ktime_get_ns();
    time.rst = ts;

    times.update(&kdata,&time);

    return 0;
}

size_t ret_r(struct pt_regs *ctx,int fd, void *buf, size_t count)
{
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;

    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    //get current time
    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->ret = ts;
    else return -1;
    
    events.increment(data);
    return 0;
}

ssize_t ext4_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;
    
    //check target file name
    ret = chk_file(iocb->ki_filp);
    //bpf_trace_printk("plz : %d\n",ret);
    if(ret!=0) return -1;
    
    //check read op
    ret = chk_op(to);
    if(ret!=0) return -1;


    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    bpf_trace_printk("haha"); 
    if(tmp)
    {
        bpf_trace_printk("why %llu\n",ts); 
        tmp->est = ts;
    }
    else return -1;

    return 0;
}

ssize_t ret_ext4(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;

    //check target file name
    ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;

    //check read op
    ret = chk_op(to);
    if(ret!=0) return -1;

    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->eet = ts;
    else return -1;

    return 0;
}

int pagecache_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,struct pagevec *pvec)
{
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;

    //check target file name
    ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;

    //check read op
    ret = chk_op(iter);
    if(ret!=0) return -1;


    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->pst = ts;
    else return -1;

    return 0;
}

int ret_pagecache(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,struct pagevec *pvec)
{
    struct data_t data = {0};

    //check process name
    int ret = chk_comm(data.comm,&(data.comm),sizeof(data.comm));
    if(ret!=0) return -1;

    //check target file name
    ret = chk_file(iocb->ki_filp);
    if(ret!=0) return -1;

    //check read op
    ret = chk_op(iter);
    if(ret!=0) return -1;

    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->pet = ts;
    else return -1;

    return 0;
}

void plug_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->bsst = ts;
    else return;

}

void ret_plug(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->bset = ts;
    else return;
}

void plugfin_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->bfst = ts;
    else return;
}

void ret_plugfin(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->bfet = ts;
    else return;
}

void io_start(struct pt_regs *ctx)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();
    //bpf_trace_printk("io : %s\n",kdata.comm);

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->sst = ts;
    else return;
}

void ret_io(struct pt_regs *ctx)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();

    u64 ts = bpf_ktime_get_ns();
    struct timeval* tmp = times.lookup(&kdata);
    if(tmp) tmp->set = ts;
    else return;
}

void nvme_start(struct pt_regs *ctx,struct nvme_queue *nvmeq, struct nvme_command *cmd,bool write_sq)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
}

void ret_nvme(struct pt_regs *ctx,struct nvme_queue *nvmeq, struct nvme_command *cmd,bool write_sq)
{
    struct key_data_t kdata = {0};
    kdata.pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
}