CC := gcc
# CFLAGS := -Wall -Werror -g -O2
CFLAGS := -Wall -g -O2
LDFLAGS :=

targets = misalignment mrt-header

all: $(targets) test

misalignment: misalignment.o
	$(CC) -o $@ $(LDFLAGS) misalignment.o

mrt-header: mrt-header.o
	$(CC) -o $@ $(LDFLAGS) mrt-header.o ../src/mrt.o

clean:
	rm -f *.o
	rm -f $(targets)

.c.o:
	$(CC) -c $(CFLAGS) $<

test: $(targets)
	./misalignment
	./mrt-header
	./corrupt-nlri.sh
	./short.sh
	./short-header.sh
