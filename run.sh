export BPF_CLANG=clang-14
export BPF_CFLAGS="-I/usr/include/x86_64-linux-gnu -D__x86_64__ -O2 -g -Wall -Werror"
export TARGET=amd64

# To compile and run the ebpf program... 
go generate ./... && go run -exec sudo .