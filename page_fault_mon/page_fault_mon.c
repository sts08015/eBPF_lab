#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <asm/types.h>

#define MAX_NAME_LEN 21

struct data_t {
    char name[MAX_NAME_LEN];
};

//key : name, val : fault number
BPF_HASH(table,struct data_t);

vm_fault_t fault_counter(struct pt_regs *ctx,struct vm_area_struct *vma)
{
    struct data_t data = {};
    
    //get name of target file
    struct file* target = vma->vm_file;
    if(target == NULL) return -1;
    struct dentry* dent = (target->f_path).dentry;
    if(dent == NULL) return -1;
    struct qstr d_name = dent->d_name;
    bpf_probe_read_kernel_str(&data.name,sizeof(data.name),d_name.name);
    
    u64* tmp = table.lookup(&data);
    if(tmp) table.increment(data);
    else
    {
        u64 cnt = 1;
        table.update(&data,&cnt);
    }
    
    return 0;
}