// +build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "tls_message.h"
#include "openssl_tracer_types.h"

// Declaring the perf submit event
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} TLS_DATA_PERF_OUTPUT SEC(".maps");

// struct bpf_map_def SEC("maps") active_ssl_read_args_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(struct my_struct),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declaring this using btf type format
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value,  char *);
  __uint(max_entries, 10000);
  __uint(map_flags, 0);
} active_ssl_read_args_map SEC(".maps");

// struct bpf_map_def SEC("maps") active_ssl_write_args_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(struct my_struct),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declare  this using btf type format
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, const char *);
  __uint(max_entries, 10000);
  __uint(map_flags, 0);
} active_ssl_write_args_map SEC(".maps");
// Declare perf output here
//  struct bpf_map_def SEC("maps") TLS_DATA_PERF_OUTPUT = {
//      .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//      .key_size = sizeof(__u32),
//      .value_size = sizeof(struct TLS_MESSAGE),
//      .max_entries = 10000,
//      .map_flags = 0,
//  };

// struct bpf_map_def SEC("maps") read_tls_map_data = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(const char *),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declare this using btf type format
// struct{
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u64);
//     __type(value, const char *);
//     __uint(max_entries, 10000);
//     __uint(map_flags, 0);
// } read_tls_map_data SEC(".maps");

// struct bpf_map_def SEC("maps") read_tls_map_timestamp = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(__u64),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declare this using btf type format
// struct{
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u64);
//     __type(value, __u64);
//     __uint(max_entries, 10000);
//     __uint(map_flags, 0);
// } read_tls_map_timestamp SEC(".maps");

// struct bpf_map_def SEC("maps") write_tls_map_data = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(const char *),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declare this using btf type format
// struct{
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u64);
//     __type(value, const char *);
//     __uint(max_entries, 10000);
//     __uint(map_flags, 0);
// } write_tls_map_data SEC(".maps");

// struct bpf_map_def SEC("maps") write_tls_map_timestamp = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(__u64),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
// Declare this using btf type format
// struct{
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u64);
//     __type(value, __u64);
//     __uint(max_entries, 10000);
//     __uint(map_flags, 0);
// } write_tls_map_timestamp SEC(".maps");

// Declare percpu array here
//  struct bpf_map_def SEC("maps") tls_data_array = {
//      .type = BPF_MAP_TYPE_PERCPU_ARRAY,
//      .key_size = sizeof(__u32),
//      .value_size = sizeof(struct TLS_MESSAGE),
//      .max_entries = 10000,
//      .map_flags = 0,
//  };
// Declare this using btf type format
struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct ssl_data_event_t);
  __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

static __inline struct ssl_data_event_t *create_ssl_data_event(struct pt_regs *ctx ,u64 current_pid_tgid)
{
  u32 kZero = 0;
  struct ssl_data_event_t *event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
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

static int process_SSL_data(struct pt_regs *ctx, u64 id, enum ssl_data_event_type type,
                            char *buf)
{
  int len = (int)PT_REGS_RC(ctx);
  if (len < 0)
  {
    return 0;
  }

  struct ssl_data_event_t *event = create_ssl_data_event(ctx, id);
  struct ssl_data_event_t event2 = {};
  if (event == NULL)
  {
    return 0;
  }

  event->type = type;
  // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
  event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);
  event2.type = type;
  asm volatile("%[len] &= 0x1fff;\n" ::[len] "+r"(len):);
  bpf_probe_read(&event->data, len & 0x1fff, buf);
  bpf_perf_event_output(ctx, &TLS_DATA_PERF_OUTPUT , BPF_F_CURRENT_CPU, event, sizeof(*event));
  return 0;
}

// Output function. This is called from the uprobe
//  static int output_tls_message(struct pt_regs* ctx, u32 bufferLen, u64 id, const char * buffer) {
//    u32 zeroPointer = 0;
//    //Lookup the TLS_MESSAGE struct in the percpu array
//    struct TLS_MESSAGE *tlsMessage = bpf_map_lookup_elem(&tls_data_array, &zeroPointer);
//    if (tlsMessage == NULL) {
//      return 0;
//    }

//   tlsMessage->ptid = id;
//   //Get the timestamp from the map
//   u64 *et = bpf_map_lookup_elem(&read_tls_map_timestamp, &id);
//   if (et == NULL) {
//     return 0;
//   }

//   tlsMessage->elapsed = bpf_ktime_get_ns() - *et;

//   u32 outputBufferLen = MAX_DATA_SIZE;
//   if (bufferLen < MAX_DATA_SIZE) {
//     outputBufferLen = bufferLen;
//   }
//   bpf_probe_read(tlsMessage->message, outputBufferLen, buffer);

//   //Submit the event
//   bpf_perf_event_output(ctx, &TLS_DATA_PERF_OUTPUT, BPF_F_CURRENT_CPU, tlsMessage, sizeof(*tlsMessage));

//   //Clear the data from the map
//   bpf_map_delete_elem(&read_tls_map_data, &id);
//   bpf_map_delete_elem(&read_tls_map_timestamp, &id);

//   return 0;
// }

SEC("uprobe/SSL_write")
int uprobe_entry_SSL_write(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  char *user_space_buf = (char *)PT_REGS_PARM2(ctx);
  bpf_printk("This is the buffer in the write functio%s:\n", user_space_buf);
  bpf_map_update_elem(&active_ssl_write_args_map, &processThreadID, &user_space_buf, 0);

  return 0;
}
SEC("uprobe/SSL_read")
int uprobe_entry_SSL_read(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  void *user_space_buf = (void *)PT_REGS_PARM2(ctx);
    bpf_printk("The value of buf is: %s", user_space_buf);

  bpf_map_update_elem(&active_ssl_read_args_map, &processThreadID, &user_space_buf, 0);
  return 0;
}

SEC("uretprobe/SSL_write")
int uprobe_return_SSL_write(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();

  // Looking up the buffer in the map
  char *buffer = bpf_map_lookup_elem(&active_ssl_write_args_map, &processThreadID);
  if (buffer != NULL)
  {
    process_SSL_data(ctx, processThreadID, kSSLWrite, buffer);
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
  char *buffer = bpf_map_lookup_elem(&active_ssl_read_args_map, &processThreadID);
  if (buffer != NULL)
  {
    process_SSL_data(ctx, processThreadID, kSSLRead, buffer);
  }
  bpf_map_delete_elem(&active_ssl_read_args_map, &processThreadID);
  return 0;
}

char _license[] SEC("license") = "GPL";
