/* mrt.h
 *
 * structures related to deserializing data from MRT files
 */

#ifndef MRT_H
#define MRT_H

#define _LARGEFILE64_SOURCE

#include <stdio.h> /* FILE */
#include <endian.h>
#include <stdint.h> /* uintXX_t */
#include <arpa/inet.h> /* ntohl */

#include "addresses.h"

/* MRT file definition found at:
 * https://datatracker.ietf.org/doc/html/rfc6396
 */

enum TRUEORFALSE {
  FALSE = 0,
  TRUE = 1
};

/* Integers in the MRT file are in big endian (network) byte order. 
 * This software is likely used on a little endian machine such as
 * intel x86, so we have to use ntohs() and ntohl() to change the integers
 * to the correct byte order. This doesn't work in a switch() statement.
 * Set up some number constants so that we can directly compare values held
 * in the file without using ntohs() first. */
enum mrt_types { /* uint16_t */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  MRT_OSPFv2 = 0x0b00, /* 11 */
  MRT_TABLE_DUMP =0x0c00, /* 12 */
  MRT_TABLE_DUMP_V2 = 0xd00, /* 13 */
  MRT_BGP4MP = 0x1000, /* 16 */
  MRT_BGP4MP_ET = 0x1100, /* 17 */
  MRT_ISIS = 0x2000, /* 32 */
  MRT_ISIS_ET = 0x2100, /* 33 */
  MRT_OSPFv3 = 0x3000, /* 48 */
  MRT_OSPFv3_ET = 0x3100 /* 49 */
# else // __BIG_ENDIAN
  MRT_OSPFv2 = 0x0b, /* 11 */
  MRT_TABLE_DUMP =0x0c, /* 12 */
  MRT_TABLE_DUMP_V2 = 0xd, /* 13 */
  MRT_BGP4MP = 0x10, /* 16 */
  MRT_BGP4MP_ET = 0x11, /* 17 */
  MRT_ISIS = 0x20, /* 32 */
  MRT_ISIS_ET = 0x21, /* 33 */
  MRT_OSPFv3 = 0x30, /* 48 */
  MRT_OSPFv3_ET = 0x31 /* 49 */
# endif // __BIG_ENDIAN
};

enum tabledumpv2_subtypes { /* uint16_t */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  PEER_INDEX_TABLE = 0x0100,
  RIB_IPV4_UNICAST = 0x0200,
  RIB_IPV4_MULTICAST = 0x0300,
  RIB_IPV6_UNICAST = 0x0400,
  RIB_IPV6_MULTICAST = 0x0500,
  RIB_GENERIC = 0x0600
# else // __BIG_ENDIAN
  PEER_INDEX_TABLE = 0x01,
  RIB_IPV4_UNICAST = 0x02,
  RIB_IPV4_MULTICAST = 0x03,
  RIB_IPV6_UNICAST = 0x04,
  RIB_IPV6_MULTICAST = 0x05,
  RIB_GENERIC = 0x06
# endif // __BIG_ENDIAN
};

enum bgp_origin_attribute {
  BGP_ORIGIN_IGP = 0,
  BGP_ORIGIN_EGP = 1,
  BGP_ORIGIN_INCOMPLETE = 2,
  BGP_ORIGIN_UNSET = 3
};

extern const char *bgp_origins[4];

enum bgp_attribute_types {
  BGP_ORIGIN = 1,
  BGP_AS_PATH = 2,
  BGP_NEXT_HOP = 3,
  BGP_MED = 4, /* Multiexit Discriminator */
  BGP_LOCAL_PREF = 5,
  BGP_ATOMIC_AGGREGATE = 6,
  BGP_AGGREGATOR = 7,
  BGP_COMMUNITIES = 8,
  BGP_MP_REACH_NLRI = 14,
  BGP_MP_UNREACH_NLRI = 15,
  BGP_EXTENDED_COMMUNITIES = 16,
  BGP_AS4_PATH = 17,
  BGP_AS4_AGGREGATOR = 18,
  BGP_LARGE_COMMUNITY = 32
};

enum bgp4mp_subtypes { /* uint16_t */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  BGP4MP_STATE_CHANGE = 0x0000,
  BGP4MP_MESSAGE = 0x0100,
  BGP4MP_MESSAGE_AS4 = 0x0400,
  BGP4MP_STATE_CHANGE_AS4 = 0x0500,
  BGP4MP_MESSAGE_LOCAL = 0x0600,
  BGP4MP_MESSAGE_AS4_LOCAL = 0x0700
# else // __BIG_ENDIAN
  BGP4MP_STATE_CHANGE = 0x00,
  BGP4MP_MESSAGE = 0x01,
  BGP4MP_MESSAGE_AS4 = 0x04,
  BGP4MP_STATE_CHANGE_AS4 = 0x05,
  BGP4MP_MESSAGE_LOCAL = 0x06,
  BGP4MP_MESSAGE_AS4_LOCAL = 0x07
# endif // __BIG_ENDIAN
};

enum bgp4mp_afis { /* address family indicators, uint16_t */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  BGP4MP_AFI_IPV4 = 0x0100,
  BGP4MP_AFI_IPV6 = 0x0200,
# else // __BIG_ENDIAN
  BGP4MP_AFI_IPV4 = 0x01,
  BGP4MP_AFI_IPV6 = 0x02,
# endif // __BIG_ENDIAN
};

enum bgp4mp_safis { /* sub-AFIs, uint8_t */
  SAFI_UNICAST = 0x01,
  SAFI_MULTICAST = 0x02
};

# if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else // __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#endif // __BIG_ENDIAN


/* Note for C newbs: a structure which ends in array[] is called a 
 * flexible array struct. You
 * malloc(sizeof(struct)+(count * sizeof(arrayelement))) to hold the
 * data instead of using a pointer and an additiona malloc.
 * It's used here to create a pointer to a point in the buffer which holds
 * different kinds of data depending on 
 */

/* Note on __attribute__ ((__packed__)):
 * if not packed, the compiler will sometimes insert dead space into the
 * structure in order to align the data types to word boundaries. Packing
 * it assures that it uses exactly the number of bytes implied by the struct,
 * which is needed so that it matches the data in the file.
 */

struct MRT_COMMON_HEADER {
  uint32_t timestamp_seconds;
  uint16_t type;
  uint16_t subtype;
  uint32_t length;
  uint8_t message[];
} __attribute__ ((__packed__));;

struct MRT_HEADER_EXTENDED {
  struct MRT_COMMON_HEADER mrt;
  uint32_t microsecond_timestamp;
  uint8_t message[];
} __attribute__ ((__packed__));;

/* BGP attribute definition found at
 * https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
 */
struct BGP_ATTRIBUTE_HEADER {
  union {
    struct {
      uint8_t unused: 4;
      uint8_t extended_length: 1;
      uint8_t partial: 1;
      uint8_t transitive: 1;
      uint8_t optional: 1;
    } __attribute__ ((__packed__));
    uint8_t flags;
  };
  uint8_t type;
  union {
    uint8_t length8;
    uint16_t length16;
  };
} __attribute__ ((__packed__));

/* https://datatracker.ietf.org/doc/html/rfc4760#section-3 */
struct BGP_MP_REACH_HEADER { /* MP_REACH_NLRI attribute */
  uint16_t address_family;           /* ipv4 / ipv6 */
  uint8_t subsequent_address_family; /* unicast / multicast */
  uint8_t next_hop_len;
  uint8_t next_hop[];
  /* uint8_t reserved; */
  /* uint8_t nlri[]; */
} __attribute__ ((__packed__));


struct BGP_UPDATE_MESSAGE {
  uint8_t marker[16];
  uint16_t length;
  uint8_t type;
  uint16_t withdrawn_routes_length;
  uint8_t routes_and_attributes[];
} __attribute__ ((__packed__));

extern const uint8_t BGP_MESSAGE_MARKER[16];

/* second part of BGP4MP header after the variable size
 * AS numbers */
struct BGP4MP_MESSAGE_HEADER2 {
  uint16_t interface_index;
  uint16_t address_family;
  union {
    struct {
      struct ipv4_address peer4;
      struct ipv4_address local4;
      struct BGP_UPDATE_MESSAGE bgp_message4[];
    } __attribute__ ((__packed__));
    struct {
      struct ipv6_address peer6;
      struct ipv6_address local6;
      struct BGP_UPDATE_MESSAGE bgp_message6[];
    } __attribute__ ((__packed__));
  };
} __attribute__ ((__packed__));

/* first part of the BGP4MP message. The outer MRT subtype determines
 * whether it's a 2-byte AS message or a 4-byte AS message. */
struct BGP4MP_MESSAGE_HEADER {
  union {
    struct {
      uint16_t peeras2;
      uint16_t localas2;
      struct BGP4MP_MESSAGE_HEADER2 head2;
    } __attribute__ ((__packed__));
    struct {
      uint32_t peeras4;
      uint32_t localas4;
      struct BGP4MP_MESSAGE_HEADER2 head4;
    } __attribute__ ((__packed__));
  };
} __attribute__ ((__packed__));


struct MRT_TRACEBACK {
  const struct MRT_COMMON_HEADER *mrt;
    /* the mrt record, which will not be modified in place once read. */
  uint8_t *aftermrt;
    /* First byte after the end of the mrt record */
  uint8_t *firstbyte;
    /* First byte containing the original data that's decoded inside
     * the mrt structure above. */
  uint8_t *afterbyte;
    /* Byte following the data decoded. Might be 1 byte past the
     * end of the mrt structure. */
  uint8_t *overflow_firstbyte;
    /* First byte where faulty information is supposed to be located.
     * Might be after aftermrt */
  uint8_t *overflow_afterbyte;
    /* Byte after the last byte where faulty information is located.
     * Might be after aftermrt */
  uint8_t *error_firstbyte;
    /* Start of faulty information, such as a length that causes
     * the buffer to overflow. */
  uint8_t *error_afterbyte;
    /* Byte after the faulty information, such as a length that causes
     * the buffer to overflow. */
  const char *tip;
    /* Information about the data format at the current level of
     * the deserialization process */
  char error[];
    /* human readable description of the error encountered. Present
     * if either overflow_firstbyte or error_firstbyte is not null. */
};

struct NLRI {
  struct MRT_TRACEBACK *trace;
  uint16_t address_family;
  uint8_t prefix_len; /* netmask */
  uint8_t fault_flag;
  union {
    struct ipv4_address ipv4;
    struct ipv6_address ipv6;
  };
};

struct NLRI_LIST {
  int num_nlri;
  int faults;
  struct MRT_TRACEBACK *error;
  struct NLRI prefixes[];
};

struct BGP_MP_REACH_NLRI {
  struct BGP_MP_REACH_HEADER *header;
  uint16_t address_family;
  uint8_t safi; /* unicast/multicast */
  union {
    struct ipv4_address next_hop;
    struct {
      struct ipv6_address global_next_hop;
      struct ipv6_address local_next_hop; /* fe80:: */
    };
  }
  struct NLRI_LIST l;
};

struct BGP_ATTRIBUTE {
  struct BGP_ATTRIBUTE_HEADER *header;
  uint8_t *content; /* after header, NULL if the header is short */
  uint8_t *after; /* after the length of the content, maybe NULL */
  uint8_t type;
  uint8_t fault;
  struct MRT_TRACEBACK *trace;
  union {
    void *unknown;
  };
};

struct BGP_ATTRIBUTES {
  int numattributes;
  uint8_t fault: 1;
  uint8_t atomic_aggregate: 1;
  uint8_t origin: 2;
  uint8_t next_hop_set: 1;
  uint8_t med_set: 1;
  uint8_t local_pref_set: 1;
  uint8_t aggregator2_set: 1;
  uint8_t aggregator4_set: 1;
  uint8_t mp_reach_nlri_set: 1;
  uint8_t mp_unreach_nlri_set: 1;
  struct ipv4_address next_hop;
  struct ipv4_address aggregator;
  uint16_t aggregator_as2;
  uint32_t aggregator_as4;
  uint32_t med;
  uint32_t local_pref;
  struct MRT_TRACEBACK *trace;
  struct BGP_ATTRIBUTE attr[];
};

struct BGP4MP_RECORD {
  struct BGP4MP_MESSAGE_HEADER *bgp;
  uint32_t peeras;
  uint32_t localas;
  struct MRT_TRACEBACK *trace_as;
  struct BGP4MP_MESSAGE_HEADER2 *header;
  struct MRT_TRACEBACK *trace_peerip;
  struct BGP_UPDATE_MESSAGE *bgp_message;
  uint8_t *withdrawals_firstbyte;
  union {
    uint8_t *withdrawals_afterbyte;
    uint16_t *path_attributes_length;
  };
  uint8_t *path_attributes_firtbyte;
  union {
    uint8_t *path_attributes_afterbyte;
    uint8_t *nlri_firstbyte;
  };
  uint8_t *nlri_afterbyte;
  struct MRT_TRACEBACK *trace_withdrawals;
  struct MRT_TRACEBACK *trace_pathattributes;
  uint8_t *nlri_bytes;
  struct MRT_TRACEBACK *trace_nlri;
};

struct MRT_RECORD {
  /* deserialized MRT message */
  union {
    struct MRT_COMMON_HEADER *mrt;
    struct MRT_HEADER_EXTENDED *extended;
  };
  uint8_t *aftermrt;
  struct MRT_TRACEBACK *trace_read;
  uint32_t seconds;
  uint32_t microseconds;
  struct MRT_TRACEBACK *trace_microseconds;
  uint8_t extended_flag;
  uint8_t read_failed;
  uint8_t *mrt_message; /* after regular or extended header */
  union {
    uint8_t *unrecognized_mrt_message;
  };
  int numerrors;
  struct MRT_TRACEBACK **trace_errors;
};


void free_mrt_message (struct MRT_RECORD *mrt);

ssize_t mread(int file, void *buffer, size_t buffersize);
/* When reading from a pipe or socket, the read will stop at the
 * the boundary of the feeding process's write even though it's
 * less than buffersize. We don't want that; we want to keep reading
 * until we have buffersize bytes.
 */

void mrt_print_trace (
  FILE *output
, struct MRT_TRACEBACK *trace
, int andrecord
);

struct MRT_RECORD *mrt_read_record(int file);

uint8_t *mrt_extended_header_process(struct MRT_RECORD *record);

void mrt_free_record (struct MRT_RECORD *mrt);

void mrt_sanity_check(void);

struct NLRI_LIST *mrt_nlri_deserialize (
  struct MRT_RECORD *record
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t *length_bytes
, uint16_t address_family
, uint8_t from_attribute_flag /* FALSE if from the outer UPDATE message */
);

void mrt_nlri_free (struct NLRI_LIST *list);

void mrt_free_attributes(struct BGP_ATTRIBUTES *attributes);

struct BGP_ATTRIBUTES *mrt_extract_attributes (
  struct MRT_RECORD *record
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t address_family
);

#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
/* This library does lots of type casts where the resulting multibyte
 * integer is not aligned with any particular byte boundary in memory.
 * x86_64 does not seem to care about this. Some legacy CPU architectures
 * do care. This code will likely crash on those architectures. Making
 * it work would require using temporary variables and memcpy()ing 
 * all over the place. That would make the code even more inscrutable.
 *
 * Sample warning this pragma suppresses:
 * firstmrt.c:775:5: warning: taking address of packed member
 * of ‘struct BGP_UPDATE_MESSAGE’ may result in an unaligned pointer
 * value [-Waddress-of-packed-member]
 * 775 |     &(bgp4mp->bgp_message->withdrawn_routes_length),
 *     |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#endif /* ifndef MRT_H */
