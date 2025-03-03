/*
 * msort.c -- Merge Sort an array of elements
 *
 * This program sorts an array of elements
 *
 */

// #define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h> /* memcpy */
#include "msort.h"

/* int (*compare)(void *element1, void *element2) */
/* return 1 (true) if element1 <= element2. Else return 0 (false) */
/* ------------------------------------------------------------------------ */

static void **merge (
/* Merge the two sorted arrays to *emptyar then copy back to *array */
  void **array
, void **emptyar
, int start1
, int start2
, int end
, int (*compare)(void*,void*)
) {
  int s1, s2, j;

  for (j=s1=start1, s2=start2; !((s1==start2)&&(s2==end)) ; j++) {
    if ((s1==start2)&&(s2!=end)) // nothing left in first array
      emptyar[j]=array[s2++];
    else if ((s1!=start2)&&(s2==end)) // nothing left in second array
      emptyar[j]=array[s1++];
    else {
      if ((*compare)(array[s1],array[s2])) emptyar[j]=array[s1++];
      else emptyar[j]=array[s2++];
    }
  }  
  /* memcpy (array+start1, emptyar+start1, sizeof(void*) * (end - start1)); */
  /* for (j=start1; j<end; j++) array[j]=emptyar[j]; */
  return array;
} /* merge */

static void **mergesort_work (
/* Mergesort the arrays. Return which array (unsorted or emptyarr) holds
 * the sorted results. */
  void **unsorted
, void **emptyar
, int start
, int end
, int (*compare)(void*,void*)
) {
/* Basic plan:
    If the array is one element long then it is sorted, return it.
    Otherwise, sort each half of it, and then merge the two sorted halves.
 */
  int mid;
  void **work_a, **work_b, **merge_to;

  if (end-start>1) {
    mid = ((end-start)/2)+start;
    work_a = mergesort_work (unsorted,emptyar,start,mid,compare);
    work_b = mergesort_work (unsorted,emptyar,mid,end,compare);
    /* if they're not in the same array (because the depth was different)
     * then copy the work_b set into work_a's array before merging */
#   ifdef DEBUG
    printf ("mergesort_work: %d, %d, %d, %s, %s\n", start, mid, end, 
      (work_a==work_b)?"a=b":"a!=b", (work_a==unsorted)?"un":"new");
#   endif
    if (work_a != work_b)
      memcpy (work_a+mid, work_b+mid, sizeof(void*) * (end - mid));
    merge_to = (work_a==unsorted)?emptyar:unsorted;
    (void) merge (work_a, merge_to, start, mid, end, compare);
    return merge_to;
  }
  else return unsorted; /* 1 element is always sorted */
}

void **mergesort (
/* Mergesort the array of pointers to data that compare() understands */
  void **unsorted
, int numelements
, int (*compare)(void*, void*)
) {
  void **emptyar, **work;

  emptyar = (void**) malloc (sizeof(void*) * numelements);
  work = mergesort_work (unsorted, emptyar, 0, numelements, compare);
  if (work != unsorted)
    memcpy (unsorted, work, sizeof(void*) * numelements);
  free (emptyar);
  return unsorted;
}

