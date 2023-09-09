#include "mrt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> /* ntohl */
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

struct TABLEDUMP_V2_PEER_ENTRY {
  union { /* 3 representations of the one-byte peer_type flags field */
    union {
      struct {
        uint8_t ip_size_flag: 1; /* 0 = IPv4, 1 = IPv6 */
        uint8_t as_size_flag: 1; /* 0 = 16 bit, 1 = 32 bit */
        uint8_t unused_flags: 6;
      } __attribute__ ((__packed__));
      uint8_t size_flags: 2;
    };
    uint8_t peer_type;
  };
  struct ipv4_address bgp_id;
  union {
    struct {
      struct ipv4_address ipv4;
      union {
        uint16_t as16_4;
        uint32_t as32_4;
      };
    };
    struct {
      struct ipv6_address ipv6;
      union {
        uint16_t as16_6;
        uint32_t as32_6;
      };
    };
  };
} __attribute__ ((__packed__));

/* sizes[TABLEDUMP_V2_PEER_ENTRY -> size_flags] */
size_t tabledump_v2_peer_entry_size[] = {1+4+4+2,1+4+16+2,1+4+4+4,1+4+16+4};

struct PEER {
  struct ipv4_address peer_id;
  uint32_t as;
  uint8_t is_ipv4;
  union {
    struct ipv4_address ipv4;
    struct ipv6_address ipv6;
  };
};

typedef struct {
  struct ipv4_address bgp_id;
  char *view;
  int peercount;
  struct PEER peers[]; 
} collector_t;

struct BGP_ATTRIBUTE_REACH_NLRI_START {
  uint16_t address_family;
  uint8_t subsequent_address_family;
  uint8_t next_hop_len;
  uint8_t next_hop[];
} __attribute__ ((__packed__));

struct RIB_AFI {
  uint32_t sequence;
  uint8_t prefix_length;
  uint8_t remainder[];
} __attribute__ ((__packed__));

struct RIB_ENTRY {
  uint16_t peer_index;
  uint32_t originated_time;
  uint16_t attribute_length;
  uint8_t attributes[];
} __attribute__ ((__packed__));

typedef struct {
  struct MRT_COMMON_HEADER *mrt;
  struct RIB_AFI *header;
  struct ipv4_address net;
  uint8_t mask;
  uint16_t num_rib_entries;
  struct RIB_ENTRY **rib_entries;
} rib_ipv4_unicast;

typedef struct {
  struct MRT_COMMON_HEADER *mrt;
} decoded_mrt;

uint32_t attributes_seen[256] = {};

void free_collector (collector_t *collector) {
  if (collector) {
    if (collector->view) free (collector->view);
    free (collector);
  }
}

collector_t *decode_peer_index (
  struct MRT_COMMON_HEADER *mrtrecord
, size_t length
, char *error
, size_t errbuflen
) {
  struct ipv4_address collector_bgp_id, *pip4;
  uint16_t view_name_length, peer_count, peer_index, *p16;
  uint8_t *p;
  void *toolong;
  char *view_name = NULL;
  struct TABLEDUMP_V2_PEER_ENTRY *peer;
  collector_t *collector;

  if (error) error[0]=0;
  if (length<(8 + sizeof(struct MRT_COMMON_HEADER))) {
    if (error) {
      snprintf(error,errbuflen-1,
        "ERROR: short peer_index: %u bytes, minimum %u",
        (unsigned int) length, (unsigned int) (8 + sizeof(struct MRT_COMMON_HEADER)));
      error[errbuflen-1]=0;
    }
    return NULL;
  }
  toolong = ((void*) mrtrecord) + length;
  pip4 = (struct ipv4_address*) mrtrecord->message;
  collector_bgp_id = *pip4;
  p16 = (uint16_t*) (mrtrecord->message + 4);
  view_name_length = *p16;
  if (view_name_length!=0) {
    view_name_length = ntohs(view_name_length);
    if ((void*) (mrtrecord->message + 6 + view_name_length) >= toolong) {
      if (error) {
        snprintf(error,errbuflen-1,
          "ERROR: short peer_index: view name %u bytes, "
          "pushes beyond mrt record len %u bytes",
          (unsigned int) view_name_length, (unsigned int) length);
        error[errbuflen-1]=0;
      }
      return NULL;
    }
    view_name = malloc(sizeof(char) * (view_name_length+1));
    memcpy(view_name, mrtrecord->message + 6, view_name_length);
    view_name[view_name_length]=0;
  } else {
    view_name = strdup("");
  }
  p16 = (uint16_t*) (mrtrecord->message + 6 + view_name_length);
  peer_count = ntohs(*p16);
  collector = (collector_t*) malloc (sizeof(collector_t) +
    (sizeof(struct PEER) * peer_count));
  collector->bgp_id = collector_bgp_id;
  collector->view = view_name;
  collector->peercount = peer_count;
  p = (uint8_t*) (mrtrecord->message + 6 + view_name_length + 4);
  for (peer_index=0; peer_index<peer_count; peer_index++) {
    uint8_t fail = FALSE;
    if ((void*) (p+tabledump_v2_peer_entry_size[0]) >= toolong) {
      fail = TRUE;
    } else {
      peer = (struct TABLEDUMP_V2_PEER_ENTRY*) p;
      p += tabledump_v2_peer_entry_size[peer->size_flags];
      if (((void*) p) > toolong) fail = TRUE;
    }
    if (fail) {
      free_collector(collector);
      if (error) {
        snprintf(error,errbuflen-1,
          "ERROR: short peer_index: peer %u of %u exceeds mrt record size "
          "of %u bytes\n",
          (unsigned int) peer_index, peer_count, (unsigned int) length);
        error[errbuflen-1]=0;
      }
      return NULL;
    }
    collector->peers[peer_index].peer_id = peer->bgp_id;
    switch (peer->ip_size_flag) {
      case TRUE: /* ipv6 */
        collector->peers[peer_index].is_ipv4 = FALSE;
        collector->peers[peer_index].ipv6 = peer->ipv6;
        switch (peer->as_size_flag) {
          case TRUE: /* 32 bit */
            collector->peers[peer_index].as = ntohl(peer->as32_6);
            break;
          default: /* 16 bit */
            collector->peers[peer_index].as = (uint32_t) ntohs(peer->as16_6);
        };
        break;
      default: /* ipv4 */
        collector->peers[peer_index].is_ipv4 = TRUE;
        collector->peers[peer_index].ipv4 = peer->ipv4;
        switch (peer->as_size_flag) {
          case TRUE: /* 32 bit */
            collector->peers[peer_index].as = htonl(peer->as32_4);
            break;
          default: /* 16 bit */
            collector->peers[peer_index].as = (uint32_t) htons(peer->as16_4);
        };
    };
  }
  return collector;
}

void print_decode_peer_index (
  struct MRT_COMMON_HEADER *mrtrecord
, size_t length
) {
  collector_t *collector;
  char error[1000];
  int i;

  collector = decode_peer_index (mrtrecord, length, error, sizeof(error));
  if (!collector) {
    fprintf(stderr,"ERROR: %s\n", error);
    return;
  }
  printf("%u: BGP collector: " PRI_IPV4 " (%s) has %u peers\n",
    (unsigned int) ntohl(mrtrecord->timestamp_seconds),
    PRI_IPV4_V(collector->bgp_id), collector->view, collector->peercount);
  for (i=0; i<collector->peercount; i++) {
    switch (collector->peers[i].is_ipv4) {
      case FALSE: /* ipv6 */
        printf ("  peer(%d) " PRI_IPV4 " @ " PRI_IPV6 " AS %u\n",
          i, PRI_IPV4_V(collector->peers[i].peer_id),
          PRI_IPV6_V(collector->peers[i].ipv6),
          collector->peers[i].as);
        break;
      default: /* ipv4 */
        printf ("  peer(%d) " PRI_IPV4 " @ " PRI_IPV4 " AS %u\n",
          i, PRI_IPV4_V(collector->peers[i].peer_id),
          PRI_IPV4_V(collector->peers[i].ipv4),
          collector->peers[i].as);
    };
  }
  free_collector(collector);
}

void free_rib_ipv4_unicast (rib_ipv4_unicast *rib)
{
  if (!rib) return;
  if (rib->rib_entries) free(rib->rib_entries);
  /* someone else frees rib->mrt */
  free (rib);
  return;
}

void printhex(char *prefix, void *ptr, int words) {
  uint32_t *p = (uint32_t*) ptr;

  if (prefix) printf("%s", prefix);
  while (words>0) {
    printf ("%08x ", ntohl(*p));
    p ++;
    words --;
  }
  if (prefix) printf("\n");
  return;
}

int print_nlri_list (
  char *saybefore
, struct NLRI_LIST *list
, uint64_t bytes_read
) {
  int i, error=FALSE;
  struct NLRI *prefix;

  if (list==NULL) return error; /* no error */

  for (i=0; i<list->num_nlri; i++) {
    prefix = &(list->prefixes[i]);
    if (prefix->address_family==BGP4MP_AFI_IPV6) {
      printf ("%s" PRI_IPV6 "/%u\n", saybefore,
        PRI_IPV6_V(prefix->ipv6), (uint32_t) prefix->prefix_len);
    } else {
      printf ("%s" PRI_IPV4 "/%u\n", saybefore,
        PRI_IPV4_V(prefix->ipv4), (uint32_t) prefix->prefix_len);
    }
    if (prefix->fault_flag && prefix->trace) {
      fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
        prefix->trace->error, (long unsigned int) bytes_read + 1);
      mrt_print_trace (stderr, prefix->trace, FALSE);
      if (prefix->trace->tip) 
        fprintf (stderr, "Information: %s\n\n", prefix->trace->tip);
      error=TRUE;
    }  
  }
  if (list->error) {
    fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
      list->error->error, (long unsigned int) bytes_read + 1);
    mrt_print_trace (stderr, list->error, FALSE);
    if (list->error->tip) 
      fprintf (stderr, "Information: %s\n\n", list->error->tip);
    error=TRUE;
  }
  return error;
}

void extract_attributes (struct RIB_ENTRY *rib) {
  void *endp;
  struct BGP_ATTRIBUTE_HEADER *attribute;
  uint16_t length;
  uint8_t *p;

  /* put a pointer at the byte after the end of the rib entry.
   * Any attribute that purports to extend to or past this pointer
   * is malformed. */
  endp = ((void*) rib) + (sizeof(struct RIB_ENTRY) 
         + (size_t) ntohs(rib->attribute_length));
  attribute = (struct BGP_ATTRIBUTE_HEADER*) rib->attributes;
  while ((void*) attribute < endp) {
    if ( /* fail if we don't have enough data to read the attribute header */
        ((((void*) attribute) + 3) >= endp) ||
        (attribute->extended_length && (((void*) attribute) + 4) >= endp) 
       ) {
      printf ("ERROR: attribute short read %u", 
        (unsigned int) (endp - (void*) attribute));
      return;
    }
    if (attribute->extended_length) {
      p = ((uint8_t*) attribute) + 4;
      length = ntohs(attribute->length16);
    } else {
      p = ((uint8_t*) attribute) + 3;
      length = (uint16_t) attribute->length8;
    }
    if (((void*)p) + length > endp) {
      printf ("ERROR: attribute short read(b) %u < %u", 
        (unsigned int) (endp - (void*) attribute), (unsigned int) length);
      return;
    }
    printf ("    found attribute %u flags 0x%x length %u\n",
      (unsigned int) attribute->type, (unsigned int) attribute->flags,
      (unsigned int) length); 
    attributes_seen[(int) attribute->type] ++;
    attribute = (struct BGP_ATTRIBUTE_HEADER*) (p + length);
  }
  return;
}

rib_ipv4_unicast *decode_rib_ipv4_unicast (
  struct MRT_COMMON_HEADER *mrtrecord
, size_t length
, char *error
, size_t errbuflen
) {
  void *toolong;
  struct RIB_AFI *afi;
  int prefixlen, ribindex;
  uint16_t *p16;
  uint8_t *p;
  rib_ipv4_unicast *rib = NULL;

  if (error) error[0]=0;
  if (length<(sizeof(struct MRT_COMMON_HEADER)+sizeof(struct RIB_AFI)+3)) {
    if (error) {
      snprintf(error,errbuflen-1,
        "ERROR: short rib_ipv4_unicast: %u bytes, minimum %u",
        (unsigned int) length,
        (unsigned int) (sizeof(struct MRT_COMMON_HEADER)+sizeof(struct RIB_AFI)+3));
      error[errbuflen-1]=0;
    }
    return NULL;
  }
  toolong = ((void*) mrtrecord) + length;
  afi = (struct RIB_AFI*) mrtrecord->message;
  if (afi->prefix_length > 32) {
    if (error) {
      snprintf(error,errbuflen-1,
        "ERROR: rib_ipv4_unicast prefix length %u is longer than 32",
        (unsigned int) afi->prefix_length);
      error[errbuflen-1]=0;
    }
    return NULL;
  }
  rib = (rib_ipv4_unicast*) malloc (sizeof(rib_ipv4_unicast));
  rib->mrt = mrtrecord;
  rib->header = afi;
  rib->net.whole = 0;
  rib->mask = afi->prefix_length;
  prefixlen = (int) rib->mask;
  prefixlen /= 8;
  if ((rib->mask % 8) != 0) prefixlen++;
  memcpy (rib->net.ad, afi->remainder, prefixlen);
  p16 = (uint16_t*) (afi->remainder + prefixlen);
  rib->num_rib_entries = ntohs(*p16);
  if (rib->num_rib_entries==0) {
    rib->rib_entries=NULL;
    return rib;
  }
  rib->rib_entries = (struct RIB_ENTRY **) malloc (
    sizeof(struct RIB_ENTRY *) * rib->num_rib_entries);
  p = (uint8_t*) (p16+1);
  for (ribindex=0; ribindex < rib->num_rib_entries; ribindex++) {
    int bad = FALSE;
    if ((void*) (p+sizeof(struct RIB_ENTRY)) >= toolong) {
      bad = TRUE;
    } else {
      rib->rib_entries[ribindex] = (struct RIB_ENTRY*) p;
      p += sizeof(struct RIB_ENTRY*) + 
        ntohs(rib->rib_entries[ribindex]->attribute_length);
      if (((void*) p) > toolong) bad = TRUE;
    }
    if (bad) {
      if (error) {
        snprintf(error,errbuflen-1,
          "ERROR: rib_ipv4_unicast rib entry %u/%u for prefix " PRI_IPV4 
          "/%u overflows MRT record length %u bytes",
          (unsigned int) ribindex, (unsigned int) rib->num_rib_entries,
          PRI_IPV4_V(rib->net), (unsigned int) rib->mask,
          (unsigned int) length);
        error[errbuflen-1]=0;
      }
      free_rib_ipv4_unicast(rib);
      return NULL;
    }
  }
  if ((void*) p != toolong) {
    fprintf(stderr,"WARNING: rib entries missing bytes %u<%u\n",
      (unsigned int) (toolong - (void*) p), (unsigned int) length);
  }
  return rib;
}

void print_rib_ipv4_unicast (
  struct MRT_COMMON_HEADER *mrtrecord
, size_t length
) {
  char error[1000];
  rib_ipv4_unicast *rib;
  uint16_t i;

  rib = decode_rib_ipv4_unicast(mrtrecord, length, error, sizeof(error));
  if (rib==NULL) {
    // fprintf(stderr,"ERROR: %s\n", error);
    printf("ERROR: %s\n", error);
    return;
  }
  printf("%u: BGP Prefix: " PRI_IPV4 "/%u (%u rib entries)\n",
    (unsigned int) ntohl(mrtrecord->timestamp_seconds),
    PRI_IPV4_V(rib->net), (unsigned int) rib->mask,
    (unsigned int) rib->num_rib_entries);
  for (i=0; i < rib->num_rib_entries; i++) {
    printf("  from peer %u @ %d with %u attribute bytes\n", 
      (unsigned int) ntohs(rib->rib_entries[i]->peer_index),
      (int) (((long long int) ntohl(rib->rib_entries[i]->originated_time)) -
      ((long long int) ntohl(mrtrecord->timestamp_seconds))),
      (unsigned int) ntohs(rib->rib_entries[i]->attribute_length));
extract_attributes(rib->rib_entries[i]);
  }
  free_rib_ipv4_unicast(rib);
}

void print_mp_reach_nlri (struct BGP_MP_REACH *reach, uint64_t bytes_read) {
  printf ("    MP_REACH_NLRI: IPv%s %scast(%u)\n", 
    (reach->address_family == BGP4MP_AFI_IPV4)?"4":"6",
    (reach->safi == BGP_SAFI_MULTICAST)?"Multi":
     ((reach->safi == BGP_SAFI_UNICAST)?"Uni":"ERROR"),
    (unsigned int) reach->safi );
  if (reach->address_family == BGP4MP_AFI_IPV6) {
    printf("      Next Hop: " PRI_IPV6 "\n", 
      PRI_IPV6_V(reach->global_next_hop));
    if (reach->local_next_hop.ad[0] != 0) 
      printf("      Next Hop: " PRI_IPV6 " (Local Scope)\n", 
        PRI_IPV6_V(reach->local_next_hop));
  } else { /* BGP4MP_AFI_IPV4 */
    printf("      Next Hop: " PRI_IPV4 "\n", PRI_IPV4_V(reach->next_hop));
  }
  (void) print_nlri_list("      Prefix: ", &(reach->l), bytes_read);
  if (reach->attribute->fault && (reach->attribute->trace)) {
    fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
      reach->attribute->trace->error, (long unsigned int) bytes_read + 1);
    mrt_print_trace (stderr, reach->attribute->trace, FALSE);
    if (reach->attribute->trace->tip) 
      fprintf (stderr, "Information: %s\n\n", reach->attribute->trace->tip);
  }
}

void print_bgp4mp (
  struct MRT_RECORD *record
, uint64_t bytes_read
) {
  struct BGP4MP_MESSAGE *m;
  struct BGP_ATTRIBUTE *a;
  int i;
  uint8_t print = TRUE;

  m = mrt_deserialize_bgp4mp_message(record);
  if (m->error) {
    fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
      m->error->error, (long unsigned int) bytes_read + 1);
    mrt_print_trace (stderr, m->error, FALSE);
    if (m->error->tip) 
      fprintf (stderr, "Information: %s\n\n", m->error->tip);
    mrt_free_bgp4mp_message(m);
    return;
  }
  if (m->header->address_family == BGP4MP_AFI_IPV4) 
    printf ("%u.%06u(byte %lu): peer AS%u (" PRI_IPV4 ")\n"
      "  withdrawn bytes %u, attribute bytes %u, nlri bytes %lu, IPv4\n",
      (unsigned int) record->seconds, (unsigned int) record->microseconds,
      bytes_read + 1, (unsigned int) m->peeras, PRI_IPV4_V((*(m->peer_ipv4))), 
      (unsigned int) (m->withdrawals_afterbyte - m->withdrawals_firstbyte),
      (unsigned int) (m->path_attributes_afterbyte - 
        m->path_attributes_firstbyte),
      (m->nlri_afterbyte - m->nlri_firstbyte));
  else /* BGP4MP_AFI_IPV4 */
    printf ("%u.%06u(byte %lu): peer AS%u\n"
      "  (" PRI_IPV6 ")\n"
      "  withdrawn bytes %u, attribute bytes %u, nlri bytes %lu, IPv6\n",
      (unsigned int) record->seconds, (unsigned int) record->microseconds,
      bytes_read + 1, (unsigned int) m->peeras, PRI_IPV6_V((*(m->peer_ipv6))), 
      (unsigned int) (m->withdrawals_afterbyte - m->withdrawals_firstbyte),
      (unsigned int) (m->path_attributes_afterbyte - 
        m->path_attributes_firstbyte),
      (m->nlri_afterbyte - m->nlri_firstbyte));
  (void) print_nlri_list("    Prefix: ", m->nlri, bytes_read);
  (void) print_nlri_list("    Withdraw: ", m->withdrawals, bytes_read);

  if (m->attributes) {
    if (m->attributes->origin != BGP_ORIGIN_UNSET) 
      printf ("    Origin: %s\n", bgp_origins[m->attributes->origin]);
    if (m->attributes->next_hop_set) 
      printf ("    IPv4 Next Hop: " PRI_IPV4 "\n",
        PRI_IPV4_V(m->attributes->next_hop));
    if (m->attributes->local_pref_set) 
      printf ("    Local Pref: %u\n", m->attributes->local_pref);
    if (m->attributes->atomic_aggregate) 
      printf ("    Atomic Aggregate = TRUE\n");
    if (m->attributes->aggregator2_set) 
      printf ("    Aggregator: " PRI_IPV4 " AS%u\n",
        PRI_IPV4_V(m->attributes->aggregator), 
        (unsigned int) m->attributes->aggregator_as2);
    if (m->attributes->aggregator4_set) 
      printf ("    Aggregator: " PRI_IPV4 " AS%u\n",
        PRI_IPV4_V(m->attributes->aggregator), 
        (unsigned int) m->attributes->aggregator_as4);
    if (m->attributes->mp_reach_nlri)
      print_mp_reach_nlri(m->attributes->mp_reach_nlri, bytes_read);
    for (i=0; i < m->attributes->numattributes; i++) {
      a = &(m->attributes->attr[i]);
      print = TRUE;
      switch (a->type) {
        case BGP_ORIGIN:
          if (m->attributes->origin != BGP_ORIGIN_UNSET) print = FALSE;
          break;
        case BGP_LOCAL_PREF:
          if (m->attributes->local_pref_set) print = FALSE;
          break;
        case BGP_ATOMIC_AGGREGATE:
          if (m->attributes->atomic_aggregate) print = FALSE;
          break;
        case BGP_NEXT_HOP:
          if (m->attributes->next_hop_set) print = FALSE;
          break;
        case BGP_AGGREGATOR:
          if (m->attributes->aggregator2_set) print = FALSE;
          break;
        case BGP_AS4_AGGREGATOR:
          if (m->attributes->aggregator4_set) print = FALSE;
          break;
        case BGP_MP_REACH_NLRI:
          if (m->attributes->mp_reach_nlri) print = FALSE;
          break;
        default:
      };
      if (print) {
        printf ("    undecoded attribute %u flags 0x%x length %u\n",
            (unsigned int) a->type, (unsigned int) a->header->flags,
            (unsigned int) (a->after - ((uint8_t*) a->header))); 
      }
      if (a->fault && a->trace) {
        fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
          a->trace->error, (long unsigned int) bytes_read + 1);
        mrt_print_trace (stderr, a->trace, FALSE);
        if (a->trace->tip) 
          fprintf (stderr, "Information: %s\n\n", a->trace->tip);
      }  
    } 
    if (m->attributes->fault && m->attributes->trace) {
      fprintf (stderr, "ERROR: %s\n  in MRT record at file position %lu\n",
        m->attributes->trace->error, (long unsigned int) bytes_read + 1);
      mrt_print_trace (stderr, m->attributes->trace, FALSE);
      if (m->attributes->trace->tip) 
        fprintf (stderr, "Information: %s\n\n", m->attributes->trace->tip);
    }
  }
  mrt_free_bgp4mp_message(m);
  return;
}

void mrt_print_decode_message (
  struct MRT_RECORD *record
, size_t length
, uint64_t bytes_read
) {
  uint8_t *message;

  record->seconds = ntohl(record->mrt->timestamp_seconds);
  // length = record->aftermrt - ((uint8_t*) record->mrt);
  message = mrt_extended_header_process(record);
  if (!message) {
    fprintf (stderr, "ERROR in MRT record at byte %lu: %s\n",
      bytes_read + 1, record->trace_microseconds->error);
    mrt_print_trace (stderr, record->trace_microseconds, FALSE);
    if (record->trace_read->tip) 
      fprintf (stderr, "Information: %s\n\n", record->trace_read->tip);
    return;
  }

  switch (record->mrt->type) {
    case MRT_TABLE_DUMP_V2:
      switch (record->mrt->subtype) {
        case PEER_INDEX_TABLE:
          print_decode_peer_index (record->mrt, length);
          break;
        case RIB_IPV4_UNICAST:
          printf ("%u: BGP dump %d (%u bytes)\n", 
            (unsigned int) ntohl(record->mrt->timestamp_seconds),
            (int) ntohs(record->mrt->subtype),
            (unsigned int) length);
          print_rib_ipv4_unicast(record->mrt, length);
          break;
        default:
          printf ("%u: unrecognized BGP dump %d (%u bytes)\n", 
            (unsigned int) ntohl(record->mrt->timestamp_seconds),
            (int) ntohs(record->mrt->subtype),
            (unsigned int) length);
      }
      break;
    case MRT_BGP4MP_ET:
    case MRT_BGP4MP:
      switch (record->mrt->subtype) {
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
          print_bgp4mp(record, bytes_read);
          break;
        case BGP4MP_STATE_CHANGE:
        case BGP4MP_STATE_CHANGE_AS4:
        case BGP4MP_MESSAGE_LOCAL:
        case BGP4MP_MESSAGE_AS4_LOCAL:
        default:
          printf ("%u.%06u: unhandled MRT_BGP4MP update subtype %d (%u bytes)\n", 
            (unsigned int) record->seconds,
            (unsigned int) record->microseconds,
            (int) ntohs(record->mrt->subtype),
            (unsigned int) length);
      }
      break;
    case MRT_TABLE_DUMP:
      printf ("%u: type %d.%d (%u bytes)\n", 
        (unsigned int) record->seconds,
        (int) ntohs(record->mrt->type), (int) ntohs(record->mrt->subtype),
        (unsigned int) length);
      break;
    default:
      fprintf (stderr,
        "ERROR: MRT record at %lu unhandled type %d.%d (%u bytes) at %u\n", 
        bytes_read + 1,
        (int) ntohs(record->mrt->type), (int) ntohs(record->mrt->subtype),
        (unsigned int) length, (unsigned int) record->seconds
        );
  }
  return ;
}

void readandprintmrtfile (const char *name) {
  int file;
  struct MRT_RECORD *record;
  uint64_t bytes_read = 0;
  size_t length;

  if (name) {
    file = open(name, O_LARGEFILE|O_RDONLY); 
  } else {
    file = fileno(stdin);
  }
  if (file<0) {
    fprintf(stderr,"ERROR: unable to open %s: %s(%d)\n", 
      (name)?name:"<stdin>", strerror(errno), errno);
    return;
  }
  while ((record = mrt_read_record(file))) {
    if (record->read_failed) break;
    length = record->aftermrt - ((uint8_t*) record->mrt);
    mrt_print_decode_message (record, length, bytes_read);
    bytes_read += (uint64_t) length;
    mrt_free_record(record);
  }
  if (record && record->read_failed) {
    fprintf (stderr, "ERROR: at byte %lu, %s\n",
      bytes_read + 1, record->trace_read->error);
    mrt_print_trace (stderr, record->trace_read, FALSE);
    if (record->trace_read->tip) 
      fprintf (stderr, "Information: %s\n\n", record->trace_read->tip);
  }
  close (file);
}

void sanitycheck(void) {
  /* make sure the compiler didn't compose the structs in an unexpected way */
  assert(sizeof(struct TABLEDUMP_V2_PEER_ENTRY) 
    == tabledump_v2_peer_entry_size[3]);
  assert(sizeof(struct RIB_AFI) == 5);
  assert(sizeof(struct RIB_ENTRY) == 8);
  return;
}

void tryit (void) {
  uint64_t a;
  uint32_t mask;
  int prefixlen;

  a = 0;
  a -= 1;
  printf("%lx\n", a);
  a = a << 3;
  printf("%lx\n", a);

  prefixlen = 22;
  mask = ((uint32_t) 0) - 1; /* 0xFFFFFFFF */
  mask = mask << (32-prefixlen);
  printf("%x/%d\n", mask, prefixlen);
 
  exit(1);
}

int main (int argc, char **argv) {
  int i;

  // tryit();
  sanitycheck();
  /* readandprintmrtfile("routeviews.route-views2.ribs.1685318400"); */
  readandprintmrtfile(NULL);
  for (i=0; i<256; i++) {
    if (attributes_seen[i] > 0) printf("Attribute %i seen %u times\n", 
      i, (unsigned int) attributes_seen[i]);
  }
  return 0;
}

