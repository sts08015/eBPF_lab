#include <uapi/linux/ptrace.h>
#include <asm/types.h>
#include <linux/fs.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

#define PROG_NAME_LEN 16

struct r_data{
    u32 st;
    u32 et;
};

struct ext4_data{
    u32 st;
    u32 et;
};

struct pc_data{
    u32 st;
    u32 et;
};

struct bsp_data{
    u32 st;
    u32 et;
};

struct bfp_data{
    u32 st;
    u32 et;
};

struct switch_data{
    u32 st;
    u32 et;
};

struct data_t {
    char comm[PROG_NAME_LEN];
    struct r_data rd;
    struct ext4_data ed;
    struct pc_data pd;
    struct bsp_data bsd;
    struct bfp_data bfd;
    struct switch_data sd;
};

BPF_PERF_OUTPUT(events);

size_t r_start(struct pt_regs *ctx)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

size_t ret_r(struct pt_regs *ctx)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

ssize_t ext4_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

ssize_t ret_ext4(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *to)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

int pagecache_start(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,struct pagevec *pvec)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

int ret_pagecache(struct pt_regs *ctx,struct kiocb *iocb, struct iov_iter *iter,struct pagevec *pvec)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    return 0;
}

void plug_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}

void ret_plug(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}

void plugfin_start(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}

void ret_plugfin(struct pt_regs *ctx,struct blk_plug *plug)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}

void io_start(struct pt_regs *ctx)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}

void ret_io(struct pt_regs *ctx)
{
    struct data_t data = {0};
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
}