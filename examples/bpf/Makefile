PROGS=ack_recognize.o

CFLAGS=-O2 -I../../include

ack_recognize.o: ack_recognize.c
	clang $(CFLAGS) -target bpf -c -o ack_recognize.o ack_recognize.c

clean:
	rm -f $(PROGS)
