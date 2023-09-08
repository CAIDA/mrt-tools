#include "../src/mrt.h"
#include <stdio.h>
#include <assert.h>
#include <string.h> /* memcpy */

struct ipv6_address ipv6_apply_netmask (
  struct ipv6_address ip
, uint8_t prefix_len
); /* in ../src/mrt.c */

void mrt_sanity_check_test(void) {
  /* make sure the compiler didn't compose the structs in an unexpected way */
  struct ipv6_address ipv6, netv6;
  struct BGP4MP_MESSAGE_HEADER2 *tr = NULL;
  uint8_t bytes[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 255, 0, 0, 0, 0 };
  uint8_t a;
  char buffer[20];

  assert (((void*) tr->bgp_message6 - (void*) tr) == 36);
  assert (((void*) tr->bgp_message4 - (void*) tr) == 12);
  assert(sizeof(struct ipv4_address) == 4);
  assert(sizeof(struct ipv6_address) == 16);
  assert(sizeof(struct BGP_ATTRIBUTE_HEADER) == 4);

  /* make sure my netmask applier is doing the right thing.
   * The IPv6 address in bytes[] should be okay for a /96 but not for a /95
   */
  memcpy (&(ipv6.ad), bytes, 16);
  netv6 = ipv6_apply_netmask(ipv6, 96);
  assert(memcmp(&ipv6, &netv6, sizeof(ipv6)) == 0);
  netv6 = ipv6_apply_netmask(ipv6, 95);
  assert(memcmp(&ipv6, &netv6, sizeof(ipv6)) != 0);

  a = 0xa5;
  snprintf(buffer, 19, PRI_U8FLAGS, PRI_U8FLAGS_V(a));
  assert(strcmp(buffer,"10100101")==0);
}

int main(void) {
  mrt_sanity_check_test();
  printf ("OK: mrt header sanity checks pass\n");
}

