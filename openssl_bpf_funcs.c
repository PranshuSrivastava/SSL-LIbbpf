#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "tls_message.h"

#define MAX_DATA_SIZE 8192

//Struct for our tls message
struct my_struct {
    const char *buf;
    size_t *len;
};


//Declaring the perf submit event
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} TLS_DATA_PERF_OUTPUT SEC(".maps");

// struct bpf_map_def SEC("maps") active_ssl_read_args_map = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(struct my_struct),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declaring this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct my_struct);
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
//Declare  this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct my_struct);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} active_ssl_write_args_map SEC(".maps");
//Declare perf output here
// struct bpf_map_def SEC("maps") TLS_DATA_PERF_OUTPUT = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(__u32),
//     .value_size = sizeof(struct TLS_MESSAGE),
//     .max_entries = 10000,
//     .map_flags = 0,
// };

// BPF_HASH(active_ssl_read_args_map, u64, struct my_struct);
// struct bpf_map_def SEC("maps") read_tls_map_data = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(const char *),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declare this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, const char *);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} read_tls_map_data SEC(".maps");

// struct bpf_map_def SEC("maps") read_tls_map_timestamp = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(__u64),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declare this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} read_tls_map_timestamp SEC(".maps");

// BPF_HASH(active_ssl_read_args_map, u64, struct my_struct);
// struct bpf_map_def SEC("maps") write_tls_map_data = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(const char *),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declare this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, const char *);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} write_tls_map_data SEC(".maps");

// struct bpf_map_def SEC("maps") write_tls_map_timestamp = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u64),
//     .value_size = sizeof(__u64),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declare this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} write_tls_map_timestamp SEC(".maps");

//Declare percpu array here
// struct bpf_map_def SEC("maps") tls_data_array = {
//     .type = BPF_MAP_TYPE_PERCPU_ARRAY,
//     .key_size = sizeof(__u32),
//     .value_size = sizeof(struct TLS_MESSAGE),
//     .max_entries = 10000,
//     .map_flags = 0,
// };
//Declare this using btf type format
struct{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct TLS_MESSAGE);
    __uint(max_entries, 10000);
    __uint(map_flags, 0);
} tls_data_array SEC(".maps");

//Output function. This is called from the uprobe
static int output_tls_message(struct pt_regs* ctx, u32 bufferLen, u64 id, const char * buffer) {
  u32 zeroPointer = 0;
  //Lookup the TLS_MESSAGE struct in the percpu array
  struct TLS_MESSAGE *tlsMessage = bpf_map_lookup_elem(&tls_data_array, &zeroPointer);
  if (tlsMessage == NULL) {
    return 0;
  }

  tlsMessage->ptid = id;
  //Get the timestamp from the map
  u64 *et = bpf_map_lookup_elem(&read_tls_map_timestamp, &id);
  if (et == NULL) {
    return 0;
  }

  tlsMessage->elapsed = bpf_ktime_get_ns() - *et;

  u32 outputBufferLen = MAX_DATA_SIZE;
  if (bufferLen < MAX_DATA_SIZE) {
    outputBufferLen = bufferLen;
  }
  bpf_probe_read(tlsMessage->message, outputBufferLen, buffer);

  //Submit the event
  bpf_perf_event_output(ctx, &TLS_DATA_PERF_OUTPUT, BPF_F_CURRENT_CPU, tlsMessage, sizeof(*tlsMessage));

  //Clear the data from the map
  bpf_map_delete_elem(&read_tls_map_data, &id);
  bpf_map_delete_elem(&read_tls_map_timestamp, &id);

  return 0;
}

SEC("uprobe/ssl_write")
int uprobe_entry_SSL_write(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();
  //Getting the address of the buffer
  struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  if (__ctx == NULL) {
    return 0;
  }
  //Reading the buffer
  char* read_buf = (char*)PT_REGS_PARM2_CORE(__ctx);

  //Updating the buffer and the timestamp in the map
  bpf_map_update_elem(&active_ssl_write_args_map, &processThreadID, &read_buf, 0);
  bpf_map_update_elem(&write_tls_map_timestamp, &processThreadID, &ts, 0);

  return 0;
}
SEC("uretprobe/ssl_write")
int uprobe_return_SSL_write(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();
  //Looking up the buffer in the map
  char** buffer = bpf_map_lookup_elem(&active_ssl_write_args_map, &processThreadID);
  if (buffer != NULL) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
      return 0;
    }

    output_tls_message(ctx, len, processThreadID, *buffer);
  }

  return 0;
}
//Attaching to the entry of the read function.
SEC("uprobe/ssl_read")
int uprobe_entry_SSL_read(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  const char* buffer = (const char*)PT_REGS_PARM2(ctx);
  //update the tiumestamp and data
  bpf_map_update_elem(&read_tls_map_timestamp, &processThreadID, &ts, 0);
  bpf_map_update_elem(&read_tls_map_data, &processThreadID, &buffer, 0);
  return 0;
}

//Attach to the return of the read function.
SEC("uretprobe/ssl_read")
int uprobe_return_SSL_read(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();

  //Looking up the buffer in the map
  const char** buffer = bpf_map_lookup_elem(&read_tls_map_data, &processThreadID);
  if (buffer != NULL) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
      return 0;
    }
    output_tls_message(ctx, len, processThreadID, *buffer);
  }
  return 0;
}