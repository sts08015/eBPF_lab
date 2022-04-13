#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <asm/types.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 delta;
};

BPF_HASH(table);

void io_mon(struct pt_regs *ctx,struct request *rq)
{
    
}