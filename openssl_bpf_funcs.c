// +build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "tls_message.h"
#include "openssl_tracer_types.h"

// Declaring the perf submit event
// struct
// {
//   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// } TLS_DATA_PERF_OUTPUT SEC(".maps");

// Declaring the ring buffer
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20); //  1MB
} TLS_DATA_RINGBUF_OUPUT SEC(".maps");

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
  __type(value, struct ssl_data);
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
  __type(value, struct ssl_data);
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

static __inline struct ssl_data_event_t *create_ssl_data_event(struct pt_regs *ctx, u64 current_pid_tgid)
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
  // bpf_probe_read(&event->data, len & 0x1fff, data->buf);
  bpf_probe_read_kernel(&event->data, event->data_len, data->buf);

  if (len > 0)
  {

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
  // Did not add pid here as it is not being used
  // Getting the address of the buffer
  // struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  // if (__ctx == NULL)
  // {
  //   return 0;
  // }
  // // Access the percpu array for read_buf
  // u32 zeroPointer = 0;
  // char *read_buf = bpf_map_lookup_elem(&data_buffer_heap, &zeroPointer);
  // if (read_buf == NULL)
  // {
  //   return 0;
  // }
  char *user_space_buf = (char *)PT_REGS_PARM2(ctx);
  // if (bpf_probe_read(read_buf, MAX_DATA_SIZE, user_space_buf) < 0)
  // {
  //   bpf_printk("Failed to read buffer\n");
  //   return 0;
  // }
  // Updating the buffer and the timestamp in the map
  struct ssl_data write_data = {};
  write_data.buf = user_space_buf;
  bpf_printk("This is the buffer in the write function:\n %s", user_space_buf);
  bpf_map_update_elem(&active_ssl_write_args_map, &processThreadID, &write_data, 0);

  return 0;
}
SEC("uprobe/SSL_read")
int uprobe_entry_SSL_read(struct pt_regs *ctx)
{
  u64 processThreadID = bpf_get_current_pid_tgid();
  // Getting the address of the buffer
  //   struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  //   if (__ctx == NULL)
  //   {
  //     return 0;
  //   }

  // // Access the percpu array for read_buf
  // u32 zeroPointer = 0;
  // char *read_buf = bpf_map_lookup_elem(&data_buffer_heap, &zeroPointer);
  // if (read_buf == NULL)
  // {
  //   return 0;
  // }
  // if (bpf_probe_read(read_buf, MAX_DATA_SIZE, user_space_buf) < 0)
  // {
  //   bpf_printk("Failed to read buffer\n");
  //   return 0;
  // }
  // update the timestamp and data
  // struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  void *user_space_buf = (void *)PT_REGS_PARM2(ctx);
  bpf_printk("This is the buffer in the read function:\n %s\n", user_space_buf);

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
    bpf_printk("Actual buffer after returing in ssl_read:%s", read_data->buf);
    process_SSL_data(ctx, processThreadID, kSSLRead, read_data);
  }
  bpf_map_delete_elem(&active_ssl_read_args_map, &processThreadID);
  return 0;
}

char _license[] SEC("license") = "GPL";