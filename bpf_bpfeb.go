// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfMyStruct struct {
	Buf [1000]int8
	Len uint64
}

type bpfTLS_MESSAGE struct {
	Elapsed int32
	Ptid    int32
	Message [8192]int8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeEntrySSL_read   *ebpf.ProgramSpec `ebpf:"uprobe_entry_SSL_read"`
	UprobeEntrySSL_write  *ebpf.ProgramSpec `ebpf:"uprobe_entry_SSL_write"`
	UprobeReturnSSL_read  *ebpf.ProgramSpec `ebpf:"uprobe_return_SSL_read"`
	UprobeReturnSSL_write *ebpf.ProgramSpec `ebpf:"uprobe_return_SSL_write"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	TLS_DATA_PERF_OUTPUT  *ebpf.MapSpec `ebpf:"TLS_DATA_PERF_OUTPUT"`
	ActiveSslReadArgsMap  *ebpf.MapSpec `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.MapSpec `ebpf:"active_ssl_write_args_map"`
	ReadTlsMapData        *ebpf.MapSpec `ebpf:"read_tls_map_data"`
	ReadTlsMapTimestamp   *ebpf.MapSpec `ebpf:"read_tls_map_timestamp"`
	TlsDataArray          *ebpf.MapSpec `ebpf:"tls_data_array"`
	WriteTlsMapData       *ebpf.MapSpec `ebpf:"write_tls_map_data"`
	WriteTlsMapTimestamp  *ebpf.MapSpec `ebpf:"write_tls_map_timestamp"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	TLS_DATA_PERF_OUTPUT  *ebpf.Map `ebpf:"TLS_DATA_PERF_OUTPUT"`
	ActiveSslReadArgsMap  *ebpf.Map `ebpf:"active_ssl_read_args_map"`
	ActiveSslWriteArgsMap *ebpf.Map `ebpf:"active_ssl_write_args_map"`
	ReadTlsMapData        *ebpf.Map `ebpf:"read_tls_map_data"`
	ReadTlsMapTimestamp   *ebpf.Map `ebpf:"read_tls_map_timestamp"`
	TlsDataArray          *ebpf.Map `ebpf:"tls_data_array"`
	WriteTlsMapData       *ebpf.Map `ebpf:"write_tls_map_data"`
	WriteTlsMapTimestamp  *ebpf.Map `ebpf:"write_tls_map_timestamp"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.TLS_DATA_PERF_OUTPUT,
		m.ActiveSslReadArgsMap,
		m.ActiveSslWriteArgsMap,
		m.ReadTlsMapData,
		m.ReadTlsMapTimestamp,
		m.TlsDataArray,
		m.WriteTlsMapData,
		m.WriteTlsMapTimestamp,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeEntrySSL_read   *ebpf.Program `ebpf:"uprobe_entry_SSL_read"`
	UprobeEntrySSL_write  *ebpf.Program `ebpf:"uprobe_entry_SSL_write"`
	UprobeReturnSSL_read  *ebpf.Program `ebpf:"uprobe_return_SSL_read"`
	UprobeReturnSSL_write *ebpf.Program `ebpf:"uprobe_return_SSL_write"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeEntrySSL_read,
		p.UprobeEntrySSL_write,
		p.UprobeReturnSSL_read,
		p.UprobeReturnSSL_write,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
