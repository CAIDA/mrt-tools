/* misalignment.c
 *
 * Test whether the current processor architecture supports 
 * integers misaligned in memory.
 * If yes, exit with a 0 status. Otherwise, exit with a non-zero status.
 *
 * Integers in MRT files start at any byte boundary they feel like.
 * Rather than memcpy() every single time, the code assumes the CPU
 * can handle integers that are not aligned to a CPU word boundary.
 * Perhaps it'll be less efficient, but it'll work. If this isn't true
 * on the instant architecture, this test will catch it early so the
 * user doesn't spend a lot of time trying to figure out why the code
 * doesn't work.
 */

#include <stdio.h>

int main (void) {
  char buffer[20];
  int *p;

  buffer[1]=5;
  p = (int*) (buffer + 1);
  /* on systems which require aligned integers, the following line should
   * crash the program.
   */
  if (*p == 0) return 1;
  printf ("OK: CPU architecture supports misaligned integers.\n");
  return 0;
} 
