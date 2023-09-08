CC := gcc
CFLAGS := -Wall -g -O2
LDFLAGS :=

targets = firstmrt

all: $(targets)

firstmrt: firstmrt.o mrt.o
	$(CC) -o $@ $(LDFLAGS) firstmrt.o mrt.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

# dependencies
firstmrt.o: firstmrt.c mrt.h addresses.h
mrt.o: mrt.c mrt.h addresses.h

