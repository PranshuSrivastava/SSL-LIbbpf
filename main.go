//This program demonstrates how to use eBPF to intercept OpenSSL calls and log the contents of the data buffers.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"


	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"github.com/cilium/ebpf/rlimit"

)

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'SSL_read' and 'SSl_write' functions are provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	binPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	read  = "SSL_read"
	write = "SSL_write"
)
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  bpf openssl_bpf_funcs.c -- -I./.

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	//Allow the current process to lock memory for eBPF.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to raise rlimit: %v", err)
	}

	//Load precompiled eBPF program and maps into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF: %v", err)
	}
	defer objs.Close()

	//Open an ELF binary and read its es.
	ex, err := link.OpenExecutable("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatalf("failed to open executable: %v", err)
	}
	upw, err := ex.Uprobe("SSL_write", objs.UprobeEntrySSL_write, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upw.Close()
	//Attach uretprobe to the SSL_write function.
	urw, err := ex.Uretprobe("SSL_write", objs.UprobeReturnSSL_write, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urw.Close()

	//Attach the uprobe to the SSL_read function.
	upr, err := ex.Uprobe("SSL_read", objs.UprobeEntrySSL_read, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upr.Close()
	//Attach uretprobe to the SSL_read function.
	urr, err := ex.Uretprobe("SSL_read", objs.UprobeReturnSSL_read, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urr.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.TLS_DATA_PERF_OUTPUT, os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create perf event reader: %v", err)
	}
	defer rd.Close()

	go func() {
		//Wait for the signal to stop the program.
		<-stopper
		log.Println("Detaching probes...")
		if err := rd.Close(); err != nil {
			log.Fatalf("failed to close perf event reader: %v", err)
		}
	}()
		log.Printf("Attaching probes...")
		//bpfEvent is generated by bpf2go from the eBPF C program.
		var event bpfEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Parse the perf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			log.Printf("%s:%s return value: %s", binPath, read, unix.ByteSliceToString(event.Line[:]))
		}
}
