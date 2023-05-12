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
	// "github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	// "golang.org/x/sys/unix"
)

const (
	// The path to the ELF binary containing the function to trace.
	// On some distributions, the 'SSL_read' and 'SSl_write' functions are provided by a
	// dynamically-linked library, so the path of the library will need
	// to be specified instead, e.g. /usr/lib/libreadline.so.8.
	// Use `ldd /bin/bash` to find these paths.
	libsslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	read       = "SSL_read"
	write      = "SSL_write"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -target amd64  bpf openssl_bpf_funcs.c -- -I./.

type bpfSslDataEventT struct {
	Type        uint32
	TimestampNs uint64
	Pid         uint32
	Tid         int32
	Data       	[8192]byte
	DataLen     [2]uint32
}


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
	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		log.Fatalf("failed to open executable: %v", err)
	}
	upw, err := ex.Uprobe(write, objs.UprobeEntrySSL_write, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upw.Close()

	//Attach uretprobe to the SSL_write function.
	urw, err := ex.Uretprobe(write, objs.UprobeReturnSSL_write, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urw.Close()

	//Attach the uprobe to the SSL_read function.
	upr, err := ex.Uprobe(read, objs.UprobeEntrySSL_read, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upr.Close()
	//Attach uretprobe to the SSL_read function.
	urr, err := ex.Uretprobe(read, objs.UprobeReturnSSL_read, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urr.Close()

	//Attach uprobe to SSL_read_ex function.
	upre, err := ex.Uprobe(read, objs.UprobeEntrySSL_readEx, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upre.Close()
	//Attach uretprobe to SSL_read_ex function.
	urre, err := ex.Uretprobe(read, objs.UprobeReturnSSL_read, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urre.Close()

	//Attach uprobe to SSL_write_ex function.
	upwe, err := ex.Uprobe(write, objs.UprobeEntrySSL_writeEx, nil)
	if err != nil {
		log.Fatalf("failed to open uprobe: %v", err)
	}
	defer upwe.Close()
	//Attach uretprobe to SSL_write_ex function.
	urwe, err := ex.Uretprobe(write, objs.UprobeReturnSSL_write, nil)
	if err != nil {
		log.Fatalf("failed to open uretprobe: %v", err)
	}
	defer urwe.Close()

	// trying ring buffer to accept events
	reader, err := ringbuf.NewReader(objs.TLS_DATA_RINGBUF_OUPUT)
	if err != nil {
		log.Fatalf("error creating ring buffer of tls_data_event: %s", err)
	}
	defer reader.Close()

	go func() {
		//Wait for the signal to stop the program.
		<-stopper
		log.Println("Detaching probes...")
		if err := reader.Close(); err != nil {
			log.Fatalf("failed to close ringbuf event reader: %v", err)
		}
	}()

	var event bpfSslDataEventT
	log.Println("Listening for events...")
	for {

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			log.Printf("reading from ringbuf tls_data_event reader: %s", err)
			continue
		} else {
			log.Printf("\n<-------->\nSuccessfully received tls_data_event from ebpf code...\n=====\n")
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}
		log.Printf("Event datalength:%v",event.DataLen[1])
		log.Printf("Event pid:%v",event.Pid)
		log.Printf("Event tid:%v",event.Tid)
		log.Printf("Event timestamp:%v",event.TimestampNs)
		log.Printf("Event type:%v",event.Type)
		log.Printf("Got the event: %v", string(event.Data[:]))
	}

}
