#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "tls_message.h"

SEC("uprobe/ssl_read")
int uprobe_entry_SSL_write(struct pt_regs* ctx) {
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    if(!__ctx)
        return 0;
    bpf_printk("uprobe_entry_SSL_write\n");
    return 0;
}