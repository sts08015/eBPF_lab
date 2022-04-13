#include <asm/types.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    char name[TASK_COMM_LEN];
    u64 read_cnt;
    u64 write_cnt;
    umode_t type;
};

BPF_ARRAY(arr,struct data_t);

static void get_name(void* buf,struct file* file, u64 size)
{
    struct dentry* dent = (file->f_path).dentry;
    struct qstr d_name = dent->d_name;
    bpf_probe_read_kernel_str(buf,size-1,d_name.name);
}

static void get_type(umode_t* buf,struct file* file)
{
    *buf = file->f_inode->i_mode;
}

ssize_t read_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {0};
    get_name(&data.name,file,TASK_COMM_LEN);
    get_type(&data.type,file);
    //look up --> inc readcnt
    return 0;
}

ssize_t readv_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {0};
    get_name(&data.name,file,TASK_COMM_LEN);
    get_type(&data.type,file);

    return 0;
}

ssize_t write_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {0};
    get_name(&data.name,file,TASK_COMM_LEN);
    get_type(&data.type,file);

    return 0;
}

ssize_t writev_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {0};
    get_name(&data.name,file,TASK_COMM_LEN);
    get_type(&data.type,file);

    return 0;
}