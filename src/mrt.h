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

enum bgp_as4_or_as2 {
  BGP_AS_PATH_24UNKNOWN = 0,
  BGP_AS_PATH_IS_AS2 = 1,
  BGP_AS_PATH_IS_AS4 = 2
};

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
  BGP_LARGE_COMMUNITIES = 32
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

enum bgp4mp_safis { /* Subsequent address family indicators, uint8_t */
  BGP_SAFI_UNICAST = 0x01,
  BGP_SAFI_MULTICAST = 0x02
};

/* https://datatracker.ietf.org/doc/html/rfc4271#section-4.3 AS_PATH types */
enum bgp4mp_as_path_segment_types {
  BGP_AS_SET = 0x01,
  BGP_AS_SEQUENCE = 0x02
};

# if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else // __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#endif // __BIG_ENDIAN

#define PRI_U8FLAGS "%c%c%c%c%c%c%c%c"
#define PRI_U8FLAGS_V(v) (v&0x80)?'1':'0', (v&0x40)?'1':'0', \
       (v&0x20)?'1':'0', (v&0x10)?'1':'0', (v&0x08)?'1':'0', \
       (v&0x04)?'1':'0', (v&0x02)?'1':'0', (v&0x01)?'1':'0'

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
  /* https://datatracker.ietf.org/doc/html/rfc4271#section-4.1 */
  uint8_t marker[16];
  uint16_t length;
  uint8_t type;
  /* https://datatracker.ietf.org/doc/html/rfc4271#section-4.3 */
  uint16_t withdrawn_routes_length;
  uint8_t routes_and_attributes[];
  /* uint8_t withdrawn_routes[];
   * uint16_t attributes_length;
   * uint8_t attributes[];
   * uint8_t updated_prefixes[];  nlri_data[]; 
   */
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
    /* First byte containing the portion of the raw *mrt data that was
     * decoded by function creating this trace */
  uint8_t *afterbyte;
    /* Byte following the data decoded. Might be 1 byte past the
     * end of the mrt structure. */
  uint8_t *overflow_firstbyte;
    /* First byte where missing information is supposed to be located but
     * a buffer length constraint put it outside of our view.
     * May be after the mrt buffer end at *aftermrt */
  uint8_t *overflow_afterbyte;
    /* Byte after the last byte where missing information is located.
     * May be after the mrt buffer end at *aftermrt */
  uint8_t *error_firstbyte;
    /* Start of faulty information, such as a length that causes
     * the buffer to overflow. */
  uint8_t *error_afterbyte;
    /* Byte after the faulty information, such as a length that causes
     * the buffer to overflow. */
  uint8_t warning: 1;
    /* This is a warning, not an error. */
  const char *tip;
    /* Information about the data format at the current level of
     * the deserialization process */
  char error[];
    /* human readable description of the error encountered. Present
     * if either overflow_firstbyte or error_firstbyte is not null. */
};

struct NLRI { /* "Network Layer Reachability Information" */
  /* a.k.a. a single decoded network prefix/route */
  struct MRT_TRACEBACK *trace;
  uint16_t address_family;
  uint8_t prefix_len; /* netmask */
  uint8_t fault_flag;
  union {
    struct ipv4_address ipv4;
    struct ipv6_address ipv6;
  };
};

struct NLRI_LIST { /* set of decoded prefixes in this record */
  int num_nlri;
  int faults;
  struct MRT_TRACEBACK *error;
  struct NLRI prefixes[];
};

struct BGP_MP_REACH { /* decoded MP_REACH_NLRI attribute */
  struct BGP_MP_REACH_HEADER *header;
  struct BGP_ATTRIBUTE *attribute;
  uint16_t address_family;
  uint8_t safi; /* unicast/multicast */
  union {
    struct ipv4_address next_hop;
    struct {
      struct ipv6_address global_next_hop;
      struct ipv6_address local_next_hop; /* fe80:: */
    };
  };
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
    struct BGP_MP_REACH *mp_reach_nlri;
    void *unknown;
  };
};

struct BGP_AS_PATH_SEGMENT {
  uint8_t type;
  uint8_t ascount;
  uint32_t as4_list[];
} __attribute__ ((__packed__));

struct BGP_AS_PATH {
  uint32_t numsegments;
  uint8_t fault;
  struct MRT_TRACEBACK *trace;
  struct BGP_ATTRIBUTE *attr;
  struct BGP_AS_PATH_SEGMENT *path[];
};

struct BGP_COMMUNITIES {
  uint32_t num;
  uint8_t fault;
  struct BGP_ATTRIBUTE *attr;
  uint32_t c[];
};

struct BGP_LARGE_COMMUNITY {
  uint32_t global;
  uint32_t local1;
  uint32_t local2;
} __attribute__ ((__packed__));

struct BGP_LARGE_COMMUNITIES {
  uint32_t num;
  uint8_t fault;
  struct BGP_ATTRIBUTE *attr;
  struct BGP_LARGE_COMMUNITY c[];
};

struct BGP_EXTENDED_COMMUNITY_TYPE_BITS {
  uint8_t type: 6;
  uint8_t transitive: 1;
  uint8_t authority: 1;
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITY_TYPE {
  union {
    uint8_t type;
    struct BGP_EXTENDED_COMMUNITY_TYPE_BITS bits;
  } __attribute__ ((__packed__));
} __attribute__ ((__packed__));


struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_OPAQUE {
  union {
    uint8_t high;
    struct BGP_EXTENDED_COMMUNITY_TYPE_BITS bits;
  } __attribute__ ((__packed__));
  uint8_t low;
  union {
    uint64_t value: 48;
    uint8_t value_bytes[6];
  } __attribute__ ((__packed__));
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITY_ONE_OCTET_OPAQUE {
  union {
    uint8_t type;
    struct BGP_EXTENDED_COMMUNITY_TYPE_BITS bits;
  } __attribute__ ((__packed__));
  union {
    uint64_t value: 56;
    uint8_t value_bytes[7];
  } __attribute__ ((__packed__));
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_AS_SPECIFIC {
  union {
    uint8_t high;
    struct BGP_EXTENDED_COMMUNITY_TYPE_BITS bits;
  } __attribute__ ((__packed__));
  uint8_t subtype;
  uint16_t global;
  uint32_t local;
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_IP {
  union {
    uint8_t high;
    struct BGP_EXTENDED_COMMUNITY_TYPE_BITS bits;
  } __attribute__ ((__packed__));
  uint8_t subtype;
  struct ipv4_address global;
  uint16_t local;
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITY {
  union {
    struct BGP_EXTENDED_COMMUNITY_TYPE type;
    struct BGP_EXTENDED_COMMUNITY_ONE_OCTET_OPAQUE one;
    struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_OPAQUE opaque;
    struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_AS_SPECIFIC as;
    struct BGP_EXTENDED_COMMUNITY_TWO_OCTET_IP ip;
    uint64_t whole;
  } __attribute__ ((__packed__));
} __attribute__ ((__packed__));

struct BGP_EXTENDED_COMMUNITIES {
  uint32_t num;
  uint8_t fault;
  struct BGP_ATTRIBUTE *attr;
  struct BGP_EXTENDED_COMMUNITY c[];
};



struct BGP_ATTRIBUTES {
  int numattributes;
  uint8_t fault: 1;
  uint8_t atomic_aggregate: 1;
  uint8_t origin: 2;
  uint8_t next_hop_set: 1;
  uint8_t med_set: 1;
  uint8_t local_pref_set: 1;
  uint8_t as2or4: 2; // AS_PATH is 2 or 4 bytes
  struct ipv4_address next_hop;
  struct ipv4_address aggregator;
  uint32_t aggregator_as;
  uint32_t med;
  uint32_t local_pref;
  struct BGP_MP_REACH *mp_reach_nlri;
  struct BGP_AS_PATH *path;
  struct BGP_COMMUNITIES *communities;
  struct BGP_LARGE_COMMUNITIES *large_communities;
  struct BGP_EXTENDED_COMMUNITIES *extended_communities;
  struct MRT_TRACEBACK *trace;
  struct BGP_ATTRIBUTE *attribute_origin;
  struct BGP_ATTRIBUTE *attribute_next_hop;
  struct BGP_ATTRIBUTE *attribute_aggregator;
  struct BGP_ATTRIBUTE *attribute_med;
  struct BGP_ATTRIBUTE *attribute_local_pref;
  struct BGP_ATTRIBUTE *attribute_as_path;
  struct BGP_ATTRIBUTE *attribute_as4_path;
  struct BGP_ATTRIBUTE attr[];
};

struct BGP4MP_MESSAGE {
  struct MRT_TRACEBACK *error; /* general error */
  struct BGP4MP_MESSAGE_HEADER *bgp4mp;
  uint32_t peeras;
  uint32_t localas;
  struct MRT_TRACEBACK *trace_as;
  struct BGP4MP_MESSAGE_HEADER2 *header;
  /* header->address_family */
  union {
    struct ipv4_address *peer_ipv4;
    struct ipv6_address *peer_ipv6;
  };
  union {
    struct ipv4_address *local_ipv4;
    struct ipv6_address *local_ipv6;
  };
  struct MRT_TRACEBACK *trace_peerip;
  struct BGP_UPDATE_MESSAGE *bgp;
  uint8_t *withdrawals_firstbyte;
  union {
    uint8_t *withdrawals_afterbyte;
    uint16_t *path_attributes_length;
  };
  uint8_t *path_attributes_firstbyte;
  union {
    uint8_t *path_attributes_afterbyte;
    uint8_t *nlri_firstbyte;
  };
  uint8_t *nlri_afterbyte;
  struct NLRI_LIST *withdrawals;
  struct NLRI_LIST *nlri;
  struct BGP_ATTRIBUTES *attributes;
  uint8_t as2_message_format; // see as2_message_format_flag below
};

/* Does the BGP4_MP message use 2-byte or 4-byte AS numbers in the AS Path
 * and aggregator attributes? It depends on the negotiated BGP extensions
 * in the BGP session, and the MRT record does not record what those are.
 * We have to infer the information. */
enum as2_message_format_flag {
  AS2_FORMAT_UNKNOWN = 0,
  AS2_FORMAT_YES = 1,
  AS2_FORMAT_NO = 2
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
    struct BGP4MP_MESSAGE *bgp4mp;
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
, uint16_t *length /* location of bytes setting length for error reporting */
, uint16_t address_family
, uint8_t from_attribute_flag /* FALSE if from the outer UPDATE message */
, size_t prefix_bytes /* add this number of bytes before return */
);

void mrt_free_nlri (
  struct NLRI_LIST *list
, uint8_t embedded /* *list itself is embedded in another structure,
                    * so don't try to free it with everything else,
                    * just free the underlying contents */
);

void mrt_free_attributes(struct BGP_ATTRIBUTES *attributes);

struct BGP_ATTRIBUTES *mrt_extract_attributes (
  struct MRT_RECORD *record
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t address_family
);

char *mrt_aspath_to_string (struct BGP_AS_PATH *path);
char *mrt_communities_to_string (struct BGP_COMMUNITIES *communities);
char *mrt_large_communities_to_string (
  struct BGP_LARGE_COMMUNITIES *communities
);
char *mrt_extended_communities_to_string (
  struct BGP_EXTENDED_COMMUNITIES *communities
);

struct BGP4MP_MESSAGE *mrt_deserialize_bgp4mp_message(
/* record->mrt->type == MRT_BGP4MP or MRT_BGP4MP_ET
 * record->mrt->subtype == BGP4MP_MESSAGE or BGP4MP_MESSAGE_AS4
 * deserialize the BGP UPDATE message between record->mrt_message and
 * record->aftermrt */
  struct MRT_RECORD *record
);

void mrt_free_bgp4mp_message (struct BGP4MP_MESSAGE *m);



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
