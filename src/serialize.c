/* serialize.c
 */

#include "serialize.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include "truefalse.h"

struct EAT_NLRIS {
  uint8_t whichlist;
  int index_in_list;
  struct NLRI_LIST *lists[2];
  uint8_t error_flag;
};

#define SERIALIZED_NLRIS_MAX 120

static struct NLRI *eat_nlri (struct EAT_NLRIS *eat) {
/* grab the next NLRI from the two lists */
  struct NLRI_LIST *l;
  struct NLRI *result;

  if (eat->whichlist > 1) return NULL; // only two lists
  l = eat->lists[eat->whichlist];
  if ((l == NULL) || (eat->index_in_list >= l->num_nlri)) {
    eat->whichlist++;
    eat->index_in_list = 0;
    return eat_nlri(eat);
  }
  
  result = &(l->prefixes[eat->index_in_list]);
  eat->index_in_list ++;
  return result;
}

static uint8_t *serialize_nlri_partial (
  struct NLRI_LIST *ipv4
, struct NLRI_LIST *ipv6
, uint8_t reach_flag
, uint32_t *result_length
) {
  struct EAT_NLRIS eat[1];
  uint32_t total_nlris;
  uint8_t *buffer, *p;
  struct SERIALIZED_NLRIS *sn;
  struct SERIALIZED_NLRI *nn;
  struct NLRI *nlri;
  int bytelen;

  memset (eat, 0, sizeof(struct EAT_NLRIS));
  eat->lists[0] = ipv4;
  eat->lists[1] = ipv6;
  total_nlris = (ipv4==NULL)?0:(uint32_t) ipv4->num_nlri;
  total_nlris += (ipv6==NULL)?0:(uint32_t) ipv6->num_nlri;
  buffer = (uint8_t*) malloc((19 * total_nlris) + 
    sizeof(struct SERIALIZED_NLRIS));
  sn = (struct SERIALIZED_NLRIS*) buffer;
  sn->reach = reach_flag;
  sn->count = 0;
  p = sn->bytes;
  while ((nlri = eat_nlri(eat))) {
    nn = (struct SERIALIZED_NLRI*) p;
    switch (nlri->address_family) {
      case BGP4MP_AFI_IPV4:
        nn->prefix_len = nlri->prefix_len + 192;
        break;
      case BGP4MP_AFI_IPV6:
        nn->prefix_len = nlri->prefix_len;
        break;
      default: // can't handle this NLRI list
        free(buffer);
        return NULL;
    };
    bytelen = (nlri->prefix_len + 7) / 8;
    memcpy (nn->prefix, nlri->bytes, bytelen);
    p += sizeof(struct SERIALIZED_NLRI) + bytelen;
    sn->count++;
    /* If I've filled the structure, start a new one */
    if (sn->count > SERIALIZED_NLRIS_MAX) {
      sn = (struct SERIALIZED_NLRIS*) p;
      sn->reach = reach_flag;
      sn->count = 0;
      p = sn->bytes;
    }
  }
  *result_length = (uint32_t) (p - buffer);
  buffer = realloc(buffer, *result_length);
  return buffer;
}

uint8_t *serialize_nlri (
  struct BGP4MP_MESSAGE *bgp4mp
, uint32_t *bytelen
) {
  struct NLRI_LIST *reach6=NULL, *unreach6=NULL;
  uint8_t *reach, *unreach;
  uint32_t reachlen, unreachlen;
  struct SERIALIZED_NLRIS *s;

  *bytelen = 0;
  // expect nlri/withdrawals to be IPv4 only
  if ((bgp4mp->header->address_family != BGP4MP_AFI_IPV4) &&
      (bgp4mp->nlri->num_nlri || bgp4mp->withdrawals->num_nlri)) return NULL;
  // expect MP_REACH/UNREACH to be IPv6 only
  if (bgp4mp->attributes->mp_reach_nlri &&
      (bgp4mp->attributes->mp_reach_nlri->address_family != BGP4MP_AFI_IPV6))
    return NULL;
  if (bgp4mp->attributes->mp_unreach_nlri &&
      (bgp4mp->attributes->mp_unreach_nlri->address_family != BGP4MP_AFI_IPV6))
    return NULL;

  if (bgp4mp->attributes->mp_reach_nlri)
    reach6 = &(bgp4mp->attributes->mp_reach_nlri->l);
  reach = serialize_nlri_partial(bgp4mp->nlri, reach6, TRUE, &reachlen);
  if (reach==NULL) return NULL;
  if (bgp4mp->attributes->mp_unreach_nlri)
    unreach6 = &(bgp4mp->attributes->mp_unreach_nlri->l);
  unreach = serialize_nlri_partial(bgp4mp->withdrawals, unreach6, 
    FALSE, &unreachlen);
  if (unreach==NULL) {
    free (reach);
    return NULL;
  }
  s = (struct SERIALIZED_NLRIS*) reach;
  if (s->count==0) {
    free(reach);
    reach = unreach;
    reachlen = unreachlen;
    unreach = NULL;
  }
  s = (struct SERIALIZED_NLRIS*) unreach;
  if (!unreach || s->count==0) {
    if (unreach) free (unreach); 
    *bytelen = reachlen;
    return reach;
  }
  *bytelen = reachlen+unreachlen;
  reach = realloc(reach, *bytelen);
  memcpy(reach+reachlen, unreach, unreachlen);
  free(unreach);
  return reach;
}

uint8_t deserialize_nlri (
  uint8_t *buffer
, uint32_t bufferlen
, struct NLRI_LIST **reach_ipv4
, struct NLRI_LIST **reach_ipv6
, struct NLRI_LIST **unreach_ipv4
, struct NLRI_LIST **unreach_ipv6
) {
  uint8_t *p, *bufend, v4flag, prefixlen, bytelen;
  struct SERIALIZED_NLRIS *sn;
  struct SERIALIZED_NLRI *n;
  struct NLRI_LIST *nlris[2][2], *l;
  size_t howmuchram;
  uint8_t index;
  int i, j;
 
  howmuchram = sizeof(struct NLRI_LIST) + (sizeof(struct NLRI) * bufferlen);
 
  for (i=0; i<2; i++) 
    for (j=0; j<2; j++) {
      nlris[i][j] = (struct NLRI_LIST*) malloc (howmuchram);
      memset (nlris[i][j], 0, howmuchram);
  }
  bufend = buffer + bufferlen;
  index = 0;
  sn = (struct SERIALIZED_NLRIS*) buffer;
  p = sn->bytes;
  while (p < bufend) {
    while (index >= sn->count) {
      index = 0;
      sn = (struct SERIALIZED_NLRIS*) p;
      p = sn->bytes;
      if (p >= bufend) break;
    }   
    if (p >= bufend) break;
    n = (struct SERIALIZED_NLRI*) p;
    v4flag = FALSE;
    prefixlen = n->prefix_len;
    if (prefixlen>=192) {
      prefixlen -= 192;
      v4flag = TRUE;
    }
    bytelen = (prefixlen + 7) / 8;
    // pick which NLRI list we're copying in to
    l = nlris[v4flag][sn->reach];
    // and copy the address prefix into it
    l->prefixes[l->num_nlri].prefix_len = prefixlen;
    l->prefixes[l->num_nlri].address_family = 
      v4flag?BGP4MP_AFI_IPV4:BGP4MP_AFI_IPV6;
    memcpy(l->prefixes[l->num_nlri].bytes, n->prefix, bytelen);
    // increment p and index to the next position
    p += sizeof(struct SERIALIZED_NLRI) + bytelen;
    index++; 
  }

  *reach_ipv4 = nlris[TRUE][TRUE];
  *reach_ipv6 = nlris[FALSE][TRUE];
  *unreach_ipv4 = nlris[TRUE][FALSE];
  *unreach_ipv6 = nlris[FALSE][FALSE];
  return TRUE;
}

static uint32_t serialize_as_path (uint8_t *buffer, struct BGP_AS_PATH *path) {
  uint8_t *p;
  uint16_t *segments, i;
  size_t length;

  if (path==NULL) return 0;
  segments = (uint16_t*) buffer;
  *segments = (uint16_t) path->numsegments;
  p = buffer + sizeof(uint16_t);
  for (i=0; i < *segments; i++) {
    length = sizeof(struct BGP_AS_PATH_SEGMENT) +
      (sizeof(uint32_t) * path->path[i]->ascount);
    memcpy (p, path->path[i], length);
    p += length;
  }
  return (uint32_t) (p - buffer);
}

uint8_t *serialize_bgp_update (
  struct MRT_RECORD *record
, uint32_t *bytelen
/* serialize the contents of an MRT record containing a BGP update */
) {
  struct BGP4MP_MESSAGE *bgp;
  struct SERIALIZED_HASHED_BGP_UPDATE *buffer; 
  size_t buffersize, length;
  uint8_t *p;
  int i;
  struct BGP_ATTRIBUTE *attribute;

  if (record->numerrors > 0) return NULL;
  switch (record->mrt->subtype) {
    case BGP4MP_MESSAGE:
    case BGP4MP_MESSAGE_AS4:
      break;
    default:
      return NULL;
  };
  bgp = record->bgp4mp;
  /* our packed version can't be much larger than the original in the MRT
   * file, so use that as the initial output buffer size */
  buffersize = sizeof(struct SERIALIZED_HASHED_BGP_UPDATE) + 
    (2 * (size_t) (record->aftermrt - ((uint8_t*) record->mrt)));
  buffer = (struct SERIALIZED_HASHED_BGP_UPDATE*) malloc (buffersize);
  memset (buffer, 0, buffersize);
  buffer->peeras = bgp->peeras; 
  buffer->localas = bgp->localas; 
  buffer->interface_index = bgp->header->interface_index;
  buffer->address_family = bgp->header->address_family;
  switch (buffer->address_family) {
    case BGP4MP_AFI_IPV4:
      buffer->peer_ipv4 = *(bgp->peer_ipv4);
      buffer->local_ipv4 = *(bgp->local_ipv4);
      break;
    case BGP4MP_AFI_IPV6:
      buffer->peer_ipv6 = *(bgp->peer_ipv6);
      buffer->local_ipv6 = *(bgp->local_ipv6);
      break;
    default:
      free(buffer);
      return NULL;
  };
  buffer->atomic_aggregate = bgp->attributes->atomic_aggregate;
  buffer->origin = bgp->attributes->origin;
  buffer->next_hop_set = bgp->attributes->next_hop_set;
  buffer->med_set = bgp->attributes->med_set;
  buffer->local_pref_set = bgp->attributes->local_pref_set;
  buffer->next_hop = bgp->attributes->next_hop;
  buffer->aggregator = bgp->attributes->aggregator;
  buffer->aggregator_as = bgp->attributes->aggregator_as;
  buffer->med = bgp->attributes->med;
  buffer->local_pref = bgp->attributes->local_pref;
  buffer->next_hop6_set = (bgp->attributes->mp_reach_nlri != NULL);
  if (buffer->next_hop6_set) {
    buffer->global_next_hop = bgp->attributes->mp_reach_nlri->global_next_hop;
    buffer->local_next_hop = bgp->attributes->mp_reach_nlri->local_next_hop;
  }
  // buffer-> = bgp->attributes->;
  buffer->as_path_bytes = serialize_as_path(
    buffer->bytes, bgp->attributes->path);
  p = buffer->bytes + buffer->as_path_bytes;
  // copy BGP attributes not explicitly extracted above
  for (i=0; i < bgp->attributes->numattributes; i++) {
    attribute = &(bgp->attributes->attr[i]);
    switch (attribute->type) {
      case BGP_ORIGIN:
      case BGP_AS_PATH:
      case BGP_NEXT_HOP:
      case BGP_MED:
      case BGP_LOCAL_PREF:
      case BGP_ATOMIC_AGGREGATE:
      case BGP_AGGREGATOR:
      case BGP_MP_REACH_NLRI:
      case BGP_MP_UNREACH_NLRI:
        continue; // this attribute handled above; don't copy
    };
    // copy the attribute
    // length is already encoded in the attribute
    length = (size_t) (attribute->after - (uint8_t*) attribute->header);
    memcpy(p, attribute->header, length);
    p += length;
  }
  buffer->other_attribute_bytes = (uint32_t) (p - 
    (buffer->bytes + buffer->as_path_bytes));
  buffer->serialized_byte_length = (uint32_t) (p - (uint8_t*) buffer);
  buffer = realloc(buffer, buffer->serialized_byte_length);
  if (bytelen) *bytelen = buffer->serialized_byte_length;

  return (uint8_t*) buffer;
}

uint32_t simplehash (
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

void hexprint(const char *prefix, const uint8_t *buffer, uint64_t bytes)
{
  const char hextable[] = "0123456789abcdef";
  const uint8_t *bufend = buffer + bytes;
  printf("%s%lu: ", prefix, bytes);
  for (; buffer < bufend; buffer++) {
    printf ("%c%c", hextable[((*buffer)&0xf0)>>4], hextable[(*buffer)&0x0f]);
  }
  printf("\n");
  return;
}

