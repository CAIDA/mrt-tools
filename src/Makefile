CC := gcc
CFLAGS := -Wall -g -O2
LDFLAGS :=

targets = bgp-explain

all: $(targets)

bgp-explain: explain.o mrt.o
	$(CC) -o $@ $(LDFLAGS) explain.o mrt.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

# dependencies
explain.o: explain.c mrt.h addresses.h
mrt.o: mrt.c mrt.h addresses.h

