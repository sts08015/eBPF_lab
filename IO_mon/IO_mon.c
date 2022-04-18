#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <linux/genhd.h>
#include <linux/blk_types.h>

struct data_t
{
    char name[DISK_NAME_LEN];
};

struct count {
    u64 read_seq_cnt;
    u64 read_rand_cnt;
    u64 write_seq_cnt;
    u64 write_rand_cnt;
};

BPF_HASH(table,struct data_t, struct count);

static u8 rw(struct request* req)
{
    struct bio* bio = req->bio;
    u8 flag = (bio->bi_opf) >> REQ_FLAG_BITS;
    return flag;
}

/*
    return 0 : sequential
    return 1 : random
*/
static u8 sr(struct request* req)
{
    struct bio * b = req->bio;
    if(b == req->biotail) return 1;
    else return 0;
}

static void determine(struct request* req,struct count *cnt)
{
    if(rw(req) == REQ_OP_READ){
        if(sr(req)){    //random
            ++(cnt->read_rand_cnt);
        }else{          //sequential
            atomic_t tmp = req->bio->__bi_cnt;
            (cnt->read_seq_cnt)+=tmp.counter;
        }
    }else if(rw(req) == REQ_OP_WRITE){
        if(sr(req)){    //random
            ++(cnt->write_rand_cnt);
        }else{          //sequential
            atomic_t tmp = req->bio->__bi_cnt;
            (cnt->write_seq_cnt)+=tmp.counter;
        }
    }
}

void IO_mon(struct pt_regs *ctx, struct request *req) {
    struct data_t buf = {0};
    struct block_device *bdev = req->part;
	const char* disk_name = req->rq_disk->disk_name;
    bpf_probe_read_kernel_str(buf.name,DISK_NAME_LEN,disk_name);
    if(buf.name[0] == 0) return;

    struct count* tmp = table.lookup(&buf);

    if(tmp == NULL){
        struct count cnt = {0};
        table.insert(&buf,&cnt);
        determine(req,&cnt);
    }else{
        determine(req,tmp);
    }
}