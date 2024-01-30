#include <stdio.h>

struct HIGHLOW {
  unsigned char low: 1;
  unsigned char middle: 6;
  unsigned char high: 1;
} __attribute__ ((__packed__));

int main (int argc, char **argv) {
  unsigned char *p;
  struct HIGHLOW h = {};

  printf ("4 >> 1 = %u\n", 4 >> 1);
  printf ("4 << 1 = %u\n", 4 << 1);
  h.high = 1;
  p = (unsigned char*) &h;
  printf ("High: %x\n", *p);

  return 0;
}

