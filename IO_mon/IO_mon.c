#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <asm/types.h>

#define DEV_NAME_LEN 10

struct data_t {
    u64 read_cnt;
    u64 write_cnt;
    char name[DEV_NAME_LEN];
};

BPF_ARRAY(arr,struct data_t);

//hmm... loading error --> kernel version issue??
void track_IO(struct pt_regs *ctx,struct request *rq)
{
    struct data_t data = {0};

}