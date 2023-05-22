// +build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "tls_message.h"
#include "openssl_tracer_types.h"


// Declaring the ring buffer
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20); //  1MB
} TLS_DATA_RINGBUF_OUPUT SEC(".maps");



struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, struct ssl_data);
  __uint(max_entries, 10000);
  __uint(map_flags, 0);
} active_ssl_read_args_map SEC(".maps");


struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, struct ssl_data);
  __uint(max_entries, 10000);
  __uint(map_flags, 0);
} active_ssl_write_args_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct ssl_data_event_t);
  __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

static __inline struct ssl_data_event_t *create_ssl_data_event(struct pt_regs *ctx, u64 current_pid_tgid)
{
  u32 kZero = 0;
  struct ssl_data_event_t *event = bpf_map_lookup_elem( &data_buffer_heap, &kZero);
  if (event == NULL)
  {
    return NULL;
  }
  const u32 kMask32b = 0xffffffff;
  event->timestamp_ns = bpf_ktime_get_ns();
  event->pid = current_pid_tgid >> 32;
  event->tid = current_pid_tgid & kMask32b;
  return event;
}

static void process_SSL_data(struct pt_regs *ctx, u64 id, enum ssl_data_event_type type,
                             struct ssl_data *data)
{
  int len = (int)PT_REGS_RC(ctx);
  // len should not be negative because -ve len represents unsuccessful call
  //  len should be atleast 16 bytes to confirm that it is http.
  if (len < 16)
  {
    return;
  }

  struct ssl_data_event_t *event = create_ssl_data_event(ctx, id);
  if (event == NULL)
  {
    bpf_printk("Cannot allocate memory for ssl_data_event");
    return;
  }
  else
  {
    bpf_printk("Memory allocated successfully...");
  }

  event->type = type;
  // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
  event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);

  // asm volatile("%[len] &= 0x1fff;\n" ::[len] "+r"(len)
  //              :);
  bpf_probe_read_str(event->data, event->data_len, data->buf);
    event->data_len = len;

    bpf_printk("Actual buffer:%s", data->buf);
    bpf_printk("event data length:%d", event->data_len);
    bpf_printk("event timestamp:%llu", event->timestamp_ns);
    bpf_printk("event pid:%lu", event->pid);
    bpf_printk("event tid:%d", event->tid);
    bpf_printk("event buffer:%s", event->data);

    // bpf_perf_event_output(ctx, &TLS_DATA_PERF_OUTPUT , BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_ringbuf_output(&TLS_DATA_RINGBUF_OUPUT, event, sizeof(*event), 0);

}


SEC("uprobe/SSL_write")
int uprobe_entry_SSL_write(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  char *user_space_buf = (char *)PT_REGS_PARM2(ctx);

  struct ssl_data write_data = {};
  write_data.buf = user_space_buf;
  bpf_map_update_elem(&active_ssl_write_args_map, &processThreadID, &write_data, 0);

  return 0;
}
SEC("uprobe/SSL_read")
int uprobe_entry_SSL_read(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  void *user_space_buf = (void *)PT_REGS_PARM2(ctx);

  struct ssl_data read_data = {};
  read_data.buf = user_space_buf;

  bpf_map_update_elem(&active_ssl_read_args_map, &processThreadID, &read_data, 0);
  return 0;
}

SEC("uretprobe/SSL_write")
int uprobe_return_SSL_write(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();

  // Looking up the buffer in the map
  struct ssl_data *write_data = bpf_map_lookup_elem(&active_ssl_write_args_map, &processThreadID);
  if (write_data != NULL)
  {
    bpf_printk("Actual buffer after returing in ssl_write:%s", write_data->buf);
    process_SSL_data(ctx, processThreadID, kSSLWrite, write_data);
  }
  bpf_map_delete_elem(&active_ssl_write_args_map, &processThreadID);
  return 0;
}

// Attach to the return of the read function.
SEC("uretprobe/SSL_read")
int uprobe_return_SSL_read(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  // Looking up the buffer in the map
  struct ssl_data *read_data = bpf_map_lookup_elem(&active_ssl_read_args_map, &processThreadID);
  if (read_data != NULL)
  {
    process_SSL_data(ctx, processThreadID, kSSLRead, read_data);
  }
  bpf_map_delete_elem(&active_ssl_read_args_map, &processThreadID);
  return 0;
}

char _license[] SEC("license") = "GPL";