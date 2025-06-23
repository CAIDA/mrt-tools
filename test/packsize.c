#include <stdio.h>
#include "../src/dedupehash.h"
#include <assert.h>
#include <stdint.h> /* uintXX_t */
#include <string.h>
#include "../src/mrt.h"

int main (int argc, char **argv) {
  uint64_t a;
  uint8_t prefix_bytes, npl, i;
  struct ipv6_address ip, ip2;

  printf ("hash_entry size=%lu\n", sizeof(struct HASH_ENTRY));
  assert (sizeof(struct HASH_ENTRY) == HASH_BUCKET_SIZE);

  a = 1UL << 40;
  printf ("a=%lu\n", a);

  npl = 0x88;
  prefix_bytes = ((npl & 0x7)?1:0);
  prefix_bytes += (npl >> 3);
  // prefix_bytes = (npl >> 3) + ((npl & 0x7)?1:0);

  printf ("prefix_bytes=%u\n", (uint32_t) prefix_bytes);

  memcpy (ip.ad, "0123456789abcdef", 16);
  ip2.upper = htonll(ip.upper);
  ip2.lower = htonll(ip.lower);
  printf ("before htonl: ");
  for (i=0; i<16; i++) {
    printf ("%c", ip.ad[i]);
  } 
  printf ("\nafter htonl: ");
  for (i=0; i<16; i++) {
    printf ("%c", ip2.ad[i]);
  } 
  printf ("\n");
  assert (memcmp (ip2.ad, "76543210fedcba98", 16) == 0);

  return 0;
}

