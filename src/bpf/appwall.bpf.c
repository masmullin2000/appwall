#include "vmlinux.h"
#include "kern_utils.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <asm-generic/errno.h>

#include "bpf_utils.h"

u8 rc_allow = TC_ACT_UNSPEC;
u8 rc_disallow = TC_ACT_SHOT;

struct allowed_file {
    unsigned long ino;
    dev_t dev;
    bool allow;
};
struct allowed_file __unused;

struct error_pid_data_t {
    pid_t tgid;
    unsigned char comm[64];
};

struct error_pid_data_t __unused2;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __be16);
    __type(value, u64);
} allowed_egress_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, pid_t);
    __type(value, u8);
} allowed_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct allowed_file);
} allowed_bins SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * sizeof(pid_t));
} error_pids SEC(".maps");

/* https://elixir.bootlin.com/linux/latest/source/include/linux/kdev_t.h */
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

static inline u32 encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline bool allowed_tgid(pid_t tgid) {
    u8 *allowed_pid = bpf_map_lookup_elem(&allowed_pids, &tgid);
    if (allowed_pid && *allowed_pid == 1) {
        return true;
    }
    return false;
}

SEC("fentry/tcp_close")
int BPF_PROG(handle_socks, struct sock *sk)
{
    u16 local_port = sk->__sk_common.skc_num;
    //bpf_printk("close %u", local_port);
    u64 zero = 0;

    int err = bpf_map_update_elem(&allowed_egress_ports, &local_port, &zero, BPF_ANY);
    if (err) {
        bpf_printk("err close %d", err);
    }

    return 0;
}

static long
is_bin_allowed(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct allowed_file *bin = (struct allowed_file*)value;
    struct allowed_file *data = (struct allowed_file*)ctx;

    if (bin->dev == data->dev && bin->ino == data->ino) {
        data->allow = true;
        return 1;
    }

    return 0;
}

SEC("fexit/security_bprm_check")
int BPF_PROG(handle_exec, struct linux_binprm *bprm, long ret) 
{
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    struct task_struct *p = BPF_CORE_READ(t, real_parent);
    pid_t tgid = BPF_CORE_READ(t, tgid);
    pid_t ppid = BPF_CORE_READ(p, tgid);
    u8 val = 1;

    struct inode *ino = bprm->file->f_inode;

    struct allowed_file f_data = {};
    f_data.ino = ino->i_ino;
    f_data.dev = encode_dev(ino->i_sb->s_dev);
    f_data.allow = false;

    unsigned long i_num = ino->i_ino;
    dev_t dev = ino->i_sb->s_dev;

    //char *f = bprm->filename;
    //bpf_printk("%s ino: %lu :: %d", f, i_num, dev);
    //bpf_printk("%s tgid %d ppid %d", f, tgid, ppid);
    long rc = bpf_for_each_map_elem(&allowed_bins, is_bin_allowed, &f_data, 0);
    //bpf_printk("allow %d %d", f_data.allow, tgid);

    //if (i_num == 48760992 || i_num == 48636544) {
    int err;
    if (f_data.allow) {
        err = bpf_map_update_elem(&allowed_pids, &tgid, &val, BPF_ANY);
        //bpf_printk("added*%d", tgid);
    } else {
        u8 *pval = bpf_map_lookup_elem(&allowed_pids, &ppid);
        if (pval && *pval) {
            err = bpf_map_update_elem(&allowed_pids, &tgid, &val, BPF_ANY);
            //bpf_printk("added %d", tgid);
            //if (err) bpf_printk("error update %d", err);
        } else {
            //err = bpf_map_delete_elem(&allowed_pids, &tgid);
        }
    }
    return 0;
}

static long
print_allowed_pids(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    if (key) {
        int *k = (int*)key;
        bpf_printk("pid list %d", *k);
        int *c = (int*)ctx;
        *c += 1;
    }
    return 0;
}

SEC("fentry/do_exit")
int BPF_PROG(handle_exit, long code)
{
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(t, pid);
    int count = 0;

    bpf_map_delete_elem(&allowed_pids, &pid);
    //bpf_for_each_map_elem(&allowed_pids, print_allowed_pids, &count, 0);  

    //bpf_printk("count is %d\n", count);
    return 0;
}

SEC("tc")
int handle_egress(struct __sk_buff *skb)
{
    int rc = rc_allow; 
    int err = 0;
    struct bpf_sock_tuple tup;
    enum ip_type ipty;
    void *dat = get_bpf_sock_tuple(skb, &tup, &ipty);
    
    if (IS_ERR(dat)) {
        goto allow_unknown;
    }
    __be16 local_port = (ipty == TCP_V4 || ipty == UDP_V4) ? tup.ipv4.sport : tup.ipv6.sport;
    local_port = bpf_ntohs(local_port);

    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    pid_t tgid = BPF_CORE_READ(t, tgid);
    pid_t ppid = BPF_CORE_READ(t, real_parent, tgid);
    u64 cookie = bpf_get_socket_cookie(skb);

    if (allowed_tgid(tgid)) {
        //bpf_printk("tgid %d::%d %llu", tgid, local_port, cookie);
        err = bpf_map_update_elem(&allowed_egress_ports, &local_port, &cookie, BPF_ANY); 
        if (err) {
            bpf_printk("error %d", err);
        }
    } else {
        u64 *allow = bpf_map_lookup_elem(&allowed_egress_ports, &local_port);
        if (allow && *allow == cookie) {
            //bpf_printk("allowed %d %d %llu", tgid, ppid, cookie);
            //bpf_printk("kern allow %llu", cookie);
        } else {
            rc = rc_disallow;
            //bpf_printk("disallow cookie %d :: %x", local_port, allow);
            //bpf_printk("kern not f %llu", cookie);
        }   
    }

    __be16 dport = (ipty == TCP_V4 || ipty == UDP_V4) ? tup.ipv4.dport : tup.ipv6.dport;
    dport = bpf_ntohs(dport);

    if (dport == 53 || dport == 5355) {
        rc = rc_allow;
    }

    if (rc == rc_disallow) {
        //if (tgid != 0) {
            //bpf_printk("disallow tgid %d port %d::%d", tgid, local_port, dport);
            void *buf = bpf_ringbuf_reserve(&error_pids, sizeof(struct error_pid_data_t), 0);
            if (buf) {
                struct error_pid_data_t ep;
                ep.tgid = tgid;
                bpf_probe_read_kernel(ep.comm, 64, BPF_CORE_READ(t, comm));
                bpf_probe_read_kernel(buf, sizeof(ep), &ep);
                bpf_ringbuf_submit(buf, 0);
            }
        //}
    } else {
        //bpf_printk("   allow tgid %d port %d::%d", tgid, local_port, dport);
    }

    return rc;
allow_unknown:
    return rc;
}

char _license[] SEC("license") = "GPL";
