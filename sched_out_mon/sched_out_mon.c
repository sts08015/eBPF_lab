#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <asm/types.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 delta;
};

BPF_HASH(table);
BPF_PERF_OUTPUT(events);

void io_start(struct pt_regs *ctx)
{
    u64 pid = (u64)(bpf_get_current_pid_tgid() >> 32);
    u64 ts = bpf_ktime_get_ns();
    table.update(&pid,&ts);
};

void ret_io_sched(struct pt_regs *ctx)
{
    struct data_t data={};
    u64 pid = (u64)(bpf_get_current_pid_tgid() >> 32);
    
    u64* tsp = table.lookup(&pid);
    if(tsp==0) return;
    
    table.delete(&pid);
    
    if(bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0)
    {
        data.pid = (u32)pid;
        data.delta = (bpf_ktime_get_ns() - *tsp);
    }
    events.perf_submit(ctx, &data, sizeof(data));
};