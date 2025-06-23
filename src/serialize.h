/* serialize.h
 *
 * Serialize/deserialize BGP update data and MRT data for
 * indexed/hashed storage
 */

#ifndef SERIALIZE_H
#define SERIALIZE_H

#define _LARGEFILE64_SOURCE

#include "mrt.h"

struct SERIALIZED_DATA {
  uint32_t length;
  uint8_t bytes[];
} __attribute__ ((__packed__));

struct SERIALIZED_NLRIS {
  uint8_t reach: 1; // reachable/announce: true. Unreach/withdraw: false.
  uint8_t count: 7; // how many NLRIs follow
  uint8_t bytes[]; // qty count of struct SERIALIZED_NLRI
} __attribute__ ((__packed__));

struct SERIALIZED_NLRI {
  uint8_t prefix_len; // 0-128 = IPv6, 192-224 = 0-32 IPv4
  uint8_t prefix[];
} __attribute__ ((__packed__));

struct FILE_ENTRY {
  union {
    uint32_t length; // network byte order (big endian)
    uint8_t bytes[4];
  };
  uint32_t timestamp_seconds;
  uint32_t microsecond_timestamp;
  uint64_t position;
} __attribute__ ((__packed__));

struct SERIALIZED_HASHED_BGP_UPDATE {
  // record->mrt->type is implicitly a BGP update
  // record->mrt->subtype is converted to BGP4MP_MESSAGE_AS4
  // seconds and microseconds not stored in hash file
  uint32_t serialized_byte_length;
  uint32_t peeras;
  uint32_t localas;
  uint16_t interface_index;
  uint16_t address_family;
  union {
    struct ipv4_address peer_ipv4;
    struct ipv6_address peer_ipv6;
  };
  union {
    struct ipv4_address local_ipv4;
    struct ipv6_address local_ipv6;
  };
  uint8_t atomic_aggregate: 1;
  uint8_t origin: 2;
  uint8_t next_hop_set: 1;
  uint8_t next_hop6_set: 1;
  uint8_t med_set: 1;
  uint8_t local_pref_set: 1;
  struct ipv4_address next_hop;
  struct ipv4_address aggregator;
  uint32_t aggregator_as;
  uint32_t med;
  uint32_t local_pref;
  struct ipv6_address global_next_hop;
  struct ipv6_address local_next_hop; /* fe80:: */
  uint32_t as_path_bytes;
  // store communities as the original undecoded BGP attributes
  //uint32_t communities_bytes;
  //uint32_t large_communities_bytes;
  //uint32_t extended_communities_bytes;
  uint32_t other_attribute_bytes;
  uint8_t bytes[];
} __attribute__ ((__packed__));

uint8_t *serialize_nlri (struct BGP4MP_MESSAGE *bgp4mp, uint32_t *bytelen);

uint8_t deserialize_nlri (
  uint8_t *buffer
, uint32_t bufferlen
, struct NLRI_LIST **reach_ipv4
, struct NLRI_LIST **reach_ipv6
, struct NLRI_LIST **unreach_ipv4
, struct NLRI_LIST **unreach_ipv6
);

uint8_t *serialize_bgp_update (
  struct MRT_RECORD *record
, uint32_t *bytelen
/* serialize the contents of an MRT record containing a BGP update */
);

#endif // SERIALIZE_H
