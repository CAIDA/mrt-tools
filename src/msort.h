/*
 * msort.h -- Merge Sort an array of elements
 *
 * This program sorts an array of elements
 *
 */

#ifndef __MERGESORT_H
#define __MERGESORT_H

/* static int compare (void *param1, void *param2); */

void **mergesort (void **unsorted, int numelements, int (*compare)());
/* Mergesort the strings */

#endif

