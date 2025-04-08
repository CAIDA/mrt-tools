CC := gcc
CFLAGS := -Wall -g -O2
LDFLAGS :=

targets = bgp-explain msort-test

all: $(targets)

include Makefile.depend

depend:
	./makedepend.sh

bgp-explain: explain.o mrt.o msort.o
	$(CC) -o $@ $(LDFLAGS) explain.o mrt.o msort.o

msort-test: msort.o msort-test.o
	$(CC) -o $@ $(LDFLAGS) msort.o msort-test.o

#compresspoc: mrt.o serialize.o compresspoc.o msort.o
#	$(CC) -o $@ $(LDFLAGS) compresspoc.o mrt.o msort.o serialize.o

compresspoc2: mrt.o serialize.o compresspoc.o msort.o dedupehash.o
	$(CC) -o $@ $(LDFLAGS) compresspoc.o mrt.o msort.o serialize.o dedupehash.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

