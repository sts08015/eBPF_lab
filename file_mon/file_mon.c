#include <asm/types.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <uapi/linux/ptrace.h>

#define MAX_PATH_LEN 30
struct data_t {
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
    u64 read_cnt;
    u64 write_cnt;
    //file type
    //IO
    //how much?
};

//key : struct data_t
BPF_HASH(table,struct data_t);

static void get_path(void* buf,struct file* file, u64 size)
{
    //struct dentry* dent = (file->f_path).dentry;
    //struct qstr d_name = dent->d_name;
    char path[MAX_PATH_LEN] = {0};
    d_path(&(file->f_path),path,MAX_PATH_LEN);
    bpf_probe_read_user_str(buf,size,path);
}

ssize_t read_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {};
    //get_path(&(data.path),file,MAX_PATH_LEN-1);
    
    return 0;
}

ssize_t readv_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {};
    //get_path(&data.path,file,MAX_PATH_LEN-1);
    
    return 0;
}

ssize_t write_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {};
    //get_path(&data.path,file,MAX_PATH_LEN-1);
    
    return 0;
}

ssize_t writev_mon(struct pt_regs *ctx,struct file *file)
{
    struct data_t data = {};
    //get_path(&data.path,file,MAX_PATH_LEN-1);
    
    return 0;
}