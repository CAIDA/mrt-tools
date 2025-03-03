CC := gcc
CFLAGS := -Wall -g -O2
LDFLAGS :=

targets = bgp-explain msort-test

all: $(targets)

bgp-explain: explain.o mrt.o msort.o
	$(CC) -o $@ $(LDFLAGS) explain.o mrt.o msort.o

msort-test: msort.o msort-test.o
	$(CC) -o $@ $(LDFLAGS) msort.o msort-test.o

serialize: mrt.o serialize.o temp.o msort.o
	$(CC) -o $@ $(LDFLAGS) temp.o mrt.o msort.o serialize.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

# dependencies
explain.o: explain.c mrt.h addresses.h
mrt.o: mrt.c mrt.h addresses.h

