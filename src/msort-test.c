/* msort-test.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "msort.h"

int string_compare (void *a, void *b) {
  return (strcmp((const char*) a, (const char*) b) <= 0);
}

int numeric_pointer_compare (void *a, void *b) {
  return (a<=b);
}

int main (void) {
  char *strings[] = { "z", "abc", "def", "007", "funky", "foobar", "test",
    "bill was here", "green" };
  void *pointers[] = { (void*) 246, (void*) 6532, (void*) 44,
    (void*) 2454, (void*) 1234, (void*) 12};
  int i;

  (void) mergesort ((void**) strings, 9, string_compare);  
  for (i=0; i<9; i++) {
    printf ("%d: %s\n", i, strings[i]);
  }
  (void) mergesort ((void**) pointers, 4, numeric_pointer_compare);  
  for (i=0; i<4; i++) {
    printf ("%d: %d\n", i, (int) (uint64_t) (pointers[i]));
  }

  (void) mergesort ((void**) pointers, 6, numeric_pointer_compare);  
  for (i=0; i<6; i++) {
    printf ("%d: %d\n", i, (int) (uint64_t) (pointers[i]));
  }

  return 0;
}
