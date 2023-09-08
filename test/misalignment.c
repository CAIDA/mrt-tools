/* misalignment.c
 *
 * Test whether the current processor architecture supports 
 * integers misaligned in memory.
 * If yes, exit with a 0 status. Otherwise, exit with a non-zero status.
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
