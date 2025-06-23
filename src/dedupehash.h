/* dedupehash.h
 *
 * Hash file for deduplicating values to be stored in a data file.
 * If the data has been seen before, return a file offset of the
 * prior copy of the data. Otherwise, save it to the end of the file 
 * and return that offset.
 */

#ifndef DEDUPEHASH_H
#define DEDUPEHASH_H

#define _LARGEFILE64_SOURCE
#include <stdint.h> /* uintXX_t */
#include <unistd.h> /* off_t */

//#define HASH_BUCKETS 2002579
//#define HASH_BUCKETS 20003167
//#define HASH_BUCKETS 5003231
#define HASH_BUCKETS 10003199

#define HASH_ENTRIES_PER_BUCKET 31
#define HASH_BUCKET_SIZE 256

// max file size 1 TB
#define HASH_MAX_OFFSET (1UL << 40UL)

// max object size 16 MiB
#define HASH_MAX_SIZE (1 << 24)

struct HASH_FILE_HEADER {
  union {
    struct {
      char magic[8];
      uint32_t hash_buckets;
      uint64_t hash_table_offset;
      uint64_t max_offset; // max allowed offset
      // stats
      uint32_t hash_buckets_used;
      uint32_t hash_max_depth;
      uint32_t total; // total times a save call has been made for a pattern
      uint32_t unique; // unique byte patterns saved
      uint32_t rawsaves; // not saved to hashfile
      uint32_t minsize;
      uint32_t maxsize;
    } __attribute__ ((__packed__));
    uint8_t bytes[HASH_BUCKET_SIZE];
  };
} __attribute__ ((__packed__));

struct HASH_FILE {
  int fd;
  int data_fd;
  struct HASH_FILE_HEADER h;
};

struct HASH_OFFSET {
  uint64_t o: 40; // max file size: 1 terabyte
} __attribute__ ((__packed__));

struct HASH_DATA_SIZE {
  uint32_t s: 24; // max object size: 16 megabytes
} __attribute__ ((__packed__));


struct HASH_ENTRY {
  union {
    struct {
      struct HASH_OFFSET offsets[HASH_ENTRIES_PER_BUCKET];
      struct HASH_DATA_SIZE sizes[HASH_ENTRIES_PER_BUCKET];
      uint64_t next_hash_offset;
    } __attribute__ ((__packed__)); // 512 bytes
    uint8_t bytes[HASH_BUCKET_SIZE];
  };
} __attribute__ ((__packed__));

struct HASH_FILE *open_hash_file (
/* Open and/or create a hash file and it associated data file.  */
  const char *hash_filename
, const char *data_filename
);

struct HASH_FILE *close_hash_file (struct HASH_FILE *h);
/* close the hash file and write stats back to the start block */

off_t hash_save_data(
/* Write a data buffer to the data file, using the hash file to deduplicate
 * it if it already exists there.  */
  struct HASH_FILE *h
, const uint8_t *buffer
, uint32_t bytes
);

#endif // DEDUPEHASH_H
