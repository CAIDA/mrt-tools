/* dedupehash.c
 */

#include "dedupehash.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include "truefalse.h"

static uint32_t simplehash (
  const uint8_t *buffer
, uint32_t length
, uint32_t buckets
) {
  const uint8_t *bufferend = buffer + length;
  uint64_t hash = 0, *p;
  size_t partial;

  partial = (size_t) (length % sizeof(uint64_t));
  if (partial != 0) {
    memcpy (&hash, buffer, partial);
    buffer += partial;
  }

  while (buffer < bufferend) {
    p = (uint64_t*) buffer;
    hash += *p;
    buffer += sizeof(uint64_t);
  }
  hash %= (uint64_t) buckets;
  return (uint32_t) hash;
}

struct HASH_FILE *close_hash_file (struct HASH_FILE *h) {
  off_t position;
  ssize_t r;

  if (!h) return NULL;
  position = lseek(h->fd, 0, SEEK_SET);
  assert (position==0);
  r = write(h->fd, &(h->h), sizeof(struct HASH_FILE_HEADER));
  assert (r==sizeof(struct HASH_FILE_HEADER));
  close (h->fd);
  if (h->fd != h->data_fd) close (h->data_fd);
  free (h);
  return NULL;
}

static struct HASH_FILE *ohf_fail(struct HASH_FILE *h) {
  if (!h) return NULL;
  if (h->fd > 0) close(h->fd);
  if ((h->data_fd > 0) && (h->fd != h->data_fd)) close(h->data_fd);
  free(h);
  return NULL;
}

struct HASH_FILE *open_hash_file (
  const char *hash_filename
, const char *data_filename
) {
  ssize_t r;
  off_t position, afterhash;
  struct HASH_FILE *h;

  assert(sizeof(off_t) >= 8);
  assert(sizeof(struct HASH_FILE_HEADER) == HASH_BUCKET_SIZE);
  assert(sizeof(struct HASH_ENTRY) == HASH_BUCKET_SIZE);

  h = (struct HASH_FILE*) malloc (sizeof(struct HASH_FILE));
  assert(h); // die now if malloc returned NULL
  memset (h, 0, sizeof(struct HASH_FILE));

  h->fd = open(hash_filename, O_RDWR | O_CREAT, 0644);
  if (h->fd < 0) return ohf_fail(h);
  if (data_filename != NULL) {
    h->data_fd = open(data_filename, O_RDWR | O_CREAT, 0644);
    if (h->data_fd < 0) return ohf_fail(h);
  } else {
    h->data_fd = h->fd;
  }

  r = read(h->fd, &(h->h), sizeof(struct HASH_FILE_HEADER));
  assert ((r==0) || (r==sizeof(struct HASH_FILE_HEADER)));
  if (r==0) {
    memcpy (h->h.magic, "bgp wdh", 8);
    h->h.hash_buckets = HASH_BUCKETS;
    h->h.hash_table_offset = sizeof(struct HASH_FILE_HEADER);
    h->h.max_offset = HASH_MAX_OFFSET;
    position = lseek(h->fd, 0, SEEK_SET);
    r = write(h->fd, &(h->h), sizeof(struct HASH_FILE_HEADER));
    if (r != HASH_BUCKET_SIZE) return close_hash_file(h);
    afterhash = (h->h.hash_table_offset +
      (sizeof(struct HASH_ENTRY) * h->h.hash_buckets));
    position = lseek(h->fd, afterhash - 1, SEEK_SET);
    if (position != (afterhash - 1)) return close_hash_file(h);
    r = write(h->fd, "", 1);
    if (r!=1) return ohf_fail(h);
  } else if (r != (ssize_t) sizeof(struct HASH_FILE_HEADER)) 
    return ohf_fail(h);
  if (memcmp(h->h.magic, "bgp wdh", 8) != 0) 
    return ohf_fail(h);
  return h;
}

static off_t return_free (off_t r, uint8_t *buffer) {
  if (buffer) free(buffer);
  return r;
}

/*
static void hexprint(
  const char *prefix
, const uint8_t *buffer
, uint64_t bytes
) {
  const char hextable[] = "0123456789abcdef";
  const uint8_t *bufend = buffer + bytes;
  printf("%s%lu: ", prefix, bytes);
  for (; buffer < bufend; buffer++) {
    printf ("%c%c", hextable[((*buffer)&0xf0)>>4], hextable[(*buffer)&0x0f]);
  }
  printf("\n");
  return;
}
*/

static off_t hash_load_bucket(
  struct HASH_FILE *h
, struct HASH_ENTRY *bucket
, off_t bucket_position
) {
  off_t position;

  position = lseek(h->fd, bucket_position, SEEK_SET);
  if (position != bucket_position) return -1;
  if (read(h->fd, bucket, sizeof(*bucket)) != sizeof(*bucket)) return -2;
  return position;
}

static off_t hash_append_bucket(
// end of full hash bucket, start a new one
  struct HASH_FILE *h
, struct HASH_ENTRY *bucket
, off_t bucket_position
) {
  struct HASH_ENTRY new_bucket = {};
  uint64_t next_offset;

  // find the end of the file and write an empty bucket
  bucket->next_hash_offset = lseek(h->fd, 0, SEEK_END);
  if (bucket->next_hash_offset <= 0) return -5;
  if (write(h->fd, &new_bucket, sizeof(new_bucket)) != sizeof(new_bucket))
    return -6;
  if (lseek(h->fd, bucket_position, SEEK_SET) != bucket_position) return -7;
  if (write(h->fd, bucket, sizeof(*bucket)) != sizeof(*bucket)) return -8;
  next_offset = bucket->next_hash_offset;
  memset (bucket, 0, sizeof(*bucket));
  return next_offset;
}

off_t hash_save_data(
  struct HASH_FILE *h
, const uint8_t *buffer
, uint32_t bytes
) {
  uint32_t hash;
  off_t bucket_position, position;
  struct HASH_ENTRY bucket;
  int i;
  uint8_t last=FALSE;
  uint8_t *check_buffer = NULL;
  uint32_t depth = 0;

  if (bytes > HASH_MAX_SIZE) return -14;
  hash = simplehash(buffer, bytes, h->h.hash_buckets);
  bucket_position = (h->h.hash_table_offset +
      (sizeof(struct HASH_ENTRY) * hash));
  while (!last) {
    position = hash_load_bucket(h, &bucket, bucket_position);
    if (position != bucket_position) 
      return return_free(bucket_position, check_buffer);
    for (i=0; i < HASH_ENTRIES_PER_BUCKET; i++) {
      // if I reach an empty entry then I need to add this data
      if (bucket.offsets[i].o==0) {
        last = TRUE;
        break;
      }
      depth ++;
      // if the data in the entry is a different size than mine then it
      // it can't be mine.
      if (bucket.sizes[i].s != bytes) continue; // for i<HASH_ENTRIES_PER_BUCKET
      // load and check the disk entry to see if it's the same as mine
      if (!check_buffer) check_buffer = (uint8_t*) malloc(bytes);
      assert (check_buffer);
      if (lseek(h->data_fd, bucket.offsets[i].o, SEEK_SET) 
          != bucket.offsets[i].o) 
        return return_free(-3, check_buffer);
      if (read(h->data_fd, check_buffer, bytes) != bytes) 
        return return_free(-4, check_buffer);
      if (memcmp(check_buffer, buffer, bytes) == 0) {
        // found it already; don't need to add
        h->h.total ++;
        return return_free(bucket.offsets[i].o, check_buffer);
      }
    }
    if ((i >= HASH_ENTRIES_PER_BUCKET) && (bucket.next_hash_offset)) {
      // follow bucket->next_hash_offset
      bucket_position = bucket.next_hash_offset;
      continue;  // while (!last) 
    }
    if (i >= HASH_ENTRIES_PER_BUCKET) {
      bucket_position = hash_append_bucket(h, &bucket, bucket_position);
      if (bucket_position < 0) 
        return return_free(bucket_position, check_buffer);
      i = 0;
      last = TRUE;
      continue;  // while (!last) 
    }
  }
  if (depth==0) h->h.hash_buckets_used ++;
  h->h.unique ++;
  h->h.total ++;
  if (h->h.total == 1) h->h.minsize = bytes;

  // add buffer to the file and add its offset to the hash bucket
  if (check_buffer) free(check_buffer);
  check_buffer = NULL;
  position = lseek(h->data_fd, 0, SEEK_END);
  if (position < 0) return -9;
  if ((position <= 0) && (h->h.total>1)) return -15;
  if (position > (off_t) HASH_MAX_OFFSET) return -10;
  bucket.sizes[i].s = bytes; 
  bucket.offsets[i].o = (uint64_t) position;
  if (write(h->data_fd, buffer, bytes) != bytes) return -11;
  if (lseek(h->fd, bucket_position, SEEK_SET) != bucket_position) return -12;
  if (write(h->fd, &bucket, sizeof(bucket)) != sizeof(bucket)) return -13;

  // update hash stats
  if (depth > h->h.hash_max_depth) h->h.hash_max_depth = depth;
  if (h->h.minsize > bytes) h->h.minsize = bytes;
  if (h->h.maxsize < bytes) h->h.maxsize = bytes;

  return bucket.offsets[i].o;
}

