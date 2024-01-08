/* mrt.c
 *
 * functions for interacting with and deserializing mrt files
 */

#include "mrt.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

const uint8_t BGP_MESSAGE_MARKER[16] =
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

const char *bgp_origins[4] = {"IGP", "EGP", "INCOMPLETE", "UNSET"};

ssize_t mread(int file, void *buffer, size_t buffersize) {
/* When reading from a pipe or socket, the read will stop at the
 * the boundary of the feeding process's write even though it's
 * less than buffersize. We don't want that; we want to keep reading
 * until we have buffersize bytes.
 */
  ssize_t r, totalr;

  totalr = 0;
  while (TRUE) {
    r = read(file, buffer, buffersize);
    if (r == buffersize) return totalr + r; /* read whole record */
    if (r == 0) return totalr; /* EOF */
    if (r < 0) return r; /* error */
    totalr += r;
    buffer += r;
    buffersize -= r;
  }
  return totalr;
}

/* "  00000000: 0000 0000 0000 0000 0000 0000 0000 0000"
 *              1 2  3 4  5 6  7 8  9 10 1112 1314 1516
 *  012345678901234567890123456789012345678901234567890123456789
 *            1         2         3         4         5
 */
static int mtr_print_line_positions[] =
  {12, 14, 17, 19, 22, 24, 27, 29, 32, 34, 37, 39, 42, 44, 47, 49};

void print_trace_line (
  FILE *output
, size_t position
, void *start
, void *after
, const char *highlights
) {
  uint16_t buffer[8] = {};
  char printbuffer[80];
  size_t len;

  if (after > start) {
    len = (size_t) (after - start);
    if (len>16) len = 16;
  } else len = 0;
  if (len>0) memcpy (buffer, start, len);
  snprintf(printbuffer, 79, 
    "  %8lx: %04x %04x %04x %04x %04x %04x %04x %04x\n",
    position, ntohs(buffer[0]), ntohs(buffer[1]), ntohs(buffer[2]), 
    ntohs(buffer[3]), ntohs(buffer[4]), ntohs(buffer[5]), ntohs(buffer[6]), 
    ntohs(buffer[7])); 
  if (len<16) {
    printbuffer[mtr_print_line_positions[len]] = '\n';
    printbuffer[mtr_print_line_positions[len]+1] = 0;
  }
  fputs(printbuffer, output);

  /* if we have a highlights line and it's not empty, print it */
  if (highlights && memcmp(highlights,"                ",16)) {
    fprintf(output, "            %c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c "
                                "%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c\n",
      highlights[0], highlights[0], highlights[1], highlights[1], 
      highlights[2], highlights[2], highlights[3], highlights[3], 
      highlights[4], highlights[4], highlights[5], highlights[5], 
      highlights[6], highlights[6], highlights[7], highlights[7], 
      highlights[8], highlights[8], highlights[9], highlights[9], 
      highlights[10], highlights[10], highlights[11], highlights[11], 
      highlights[12], highlights[12], highlights[13], highlights[13], 
      highlights[14], highlights[14], highlights[15], highlights[15]);
  }
  return;
}

static const size_t mrt_sanity_max_print = 0x200;

void mrt_print_trace (
  FILE *output
, struct MRT_TRACEBACK *trace
, int andrecord
) {
  uint8_t *first, *last, *p;
  char highlights[16];
  int offset, i;

  fflush(stdout);
  first = trace->firstbyte;
  if ( trace->overflow_firstbyte && (first > trace->overflow_firstbyte) )
    first = trace->overflow_firstbyte;
  if ( trace->error_firstbyte && (first > trace->error_firstbyte) )
    first = trace->error_firstbyte;
  if (first < (uint8_t*) trace->mrt) first = (uint8_t*) trace->mrt;
  /* print starting at a byte number divisible by 16 */
  offset = ((int) (first - ((uint8_t*) trace->mrt))) & 0xF;
  first -= offset;
  /* print at least 4 bytes before the highlighted byte unless that's
   * before the start of the mrt record */
  if ((first > (uint8_t*) trace->mrt) && 
      ((trace->firstbyte - first) < 4) ) {
    first -= 16; 
  }
  /* if told to print the whole record, then ignore all that and print the
   * whole record */
  if (andrecord) first = (uint8_t*) trace->mrt;

  last = trace->afterbyte;
  if ( trace->error_afterbyte && (last < trace->error_afterbyte) )
    last = trace->error_afterbyte;
  if ( trace->overflow_afterbyte && (last < trace->overflow_afterbyte) )
    last = trace->overflow_afterbyte;
  offset = ((int) (last - ((uint8_t*) trace->mrt))) & 0xF;
  last += (16 - offset);

  /* Be somewhat reasonable about allegedly oversized records */
  if (last - first > mrt_sanity_max_print) last = first + mrt_sanity_max_print;

  /* if told to print the whole record, then ignore all that and print the
   * whole record */
  if (andrecord || (last > trace->aftermrt)) last = trace->aftermrt;

  /* If an overflow extends past the end of the record, print one line of
   * that too for clarity. */
  if (trace->overflow_afterbyte > last) {
    /*if ( (((last - (uint8_t*) trace->mrt) >> 2) !=
         ((trace->overflow_afterbyte - (uint8_t*) trace->mrt) >> 2)) ||
         (((last - (uint8_t*) trace->mrt) & 0xf) == 0)*/
    if ( (((last  - (uint8_t*) trace->mrt)-1) >> 2) !=
         ((trace->overflow_afterbyte - (uint8_t*) trace->mrt) >> 2)
       ) last += 16;
  }

  /* print at least 4 bytes following the flagged data unless that
   * would extend past the end of the mrt record */
  if ((trace->afterbyte + 4 < last) && 
      ((trace->afterbyte + 4) < trace->aftermrt) ) {
    last += 16;
  }

  while (first < last) {
    memset (highlights, ' ', 16);
    for (p=first, i=0; i<16; i++, p++) {
      if ((p>=trace->overflow_firstbyte) && (p<trace->overflow_afterbyte))
        highlights[i] = 'o';
      if ((p>=trace->firstbyte) && (p<trace->afterbyte))
        highlights[i] = '^';
      if ((p>=trace->error_firstbyte) && (p<trace->error_afterbyte))
        highlights[i] = '!';
      /* else keep ' ' */
    }
    print_trace_line(output, (size_t) (first - ((uint8_t*) trace->mrt)), 
      first, trace->aftermrt, highlights);
    first += 16;
  }
  return;
}

void mrt_free_record (struct MRT_RECORD *mrt)
{
  if (!mrt) return;
  if (mrt->trace_microseconds) free(mrt->trace_microseconds);
  if (mrt->trace_read) free(mrt->trace_read);
  if (mrt->mrt) free(mrt->mrt);
  /* mrt->traceerrors[] are copies of traces elsewhere in the structure
   * don't independently free them. */
  if (mrt->trace_errors) free(mrt->trace_errors);
  free(mrt);
  return;
}

static void push_error(struct MRT_RECORD *mrt, struct MRT_TRACEBACK *tr) 
{
  if (mrt->numerrors) {
    mrt->trace_errors = (struct MRT_TRACEBACK **) realloc(
      mrt->trace_errors, sizeof(struct MRT_TRACEBACK *) * (mrt->numerrors+1));
  } else {
    mrt->trace_errors = (struct MRT_TRACEBACK **) malloc(
      sizeof(struct MRT_TRACEBACK *));
  }
  mrt->trace_errors[mrt->numerrors] = tr;
  mrt->numerrors ++;
  return;
}

static struct MRT_TRACEBACK *newtraceback (
  struct MRT_RECORD *record
, char *error
, const char *tip
) {
  size_t trsize;
  struct MRT_TRACEBACK *trace;

  if (error == NULL) error="";

  trsize = sizeof(struct MRT_TRACEBACK) + (strlen(error)+1);
  trace = (struct MRT_TRACEBACK*) malloc(trsize);
  assert(trace != NULL);
  memset(trace, 0, trsize);
  strcpy(trace->error, error);
  trace->mrt = record->mrt;
  trace->aftermrt = record->aftermrt;
  trace->tip = tip;
  if (*error != 0) push_error(record, trace);

  return trace;
}

struct ipv4_address ipv4_apply_netmask (
  struct ipv4_address ip
, uint8_t prefix_len
) {
  uint32_t netmask;

  if (prefix_len > 32) prefix_len = 32;
  netmask = 0;
  netmask -= 1; /* 0xFFFFFFFFFF */
  netmask = netmask << (32 - prefix_len);
  ip.whole &= htonl(netmask);
  return ip;
}

struct ipv6_address ipv6_apply_netmask (
  struct ipv6_address ip
, uint8_t prefix_len
) {
  uint64_t upper_netmask, lower_netmask;

  upper_netmask = 0;
  upper_netmask -= 1; /* 0xFFFFF... */
  lower_netmask = upper_netmask;
  if (prefix_len > 128) prefix_len = 128;
  if (prefix_len > 64) {
    lower_netmask = lower_netmask << (128 - prefix_len);
  } else {
    lower_netmask = 0;
    upper_netmask = upper_netmask << (64 - prefix_len);
  }
  ip.upper &= htonll(upper_netmask);
  ip.lower &= htonll(lower_netmask);
  return ip;
}

int mrt_count_attributes (
  uint8_t *p
, uint8_t *after
) {
  int num = 0;
  struct BGP_ATTRIBUTE_HEADER *attribute;

  for (num=0; p < after; num++) {
    if ((after - p) < (sizeof(struct BGP_ATTRIBUTE_HEADER)-1)) return num+1;
    attribute = (struct BGP_ATTRIBUTE_HEADER*) p;
    if ( (attribute->extended_length) && 
         ((after - p) < sizeof(struct BGP_ATTRIBUTE_HEADER)) )
      return num+1;
    if (attribute->extended_length) 
      p += sizeof(struct BGP_ATTRIBUTE_HEADER) + ntohs(attribute->length16);
    else
      p += sizeof(struct BGP_ATTRIBUTE_HEADER) - 1 + attribute->length8;
  }
  return num;
}

void mrt_free_attributes(struct BGP_ATTRIBUTES *attributes)
{
  int i;
  if (!attributes) return;
  for (i=0; i < attributes->numattributes; i++) {
    if (attributes->attr[i].trace)
      free(attributes->attr[i].trace);
    switch (attributes->attr[i].type) {
      /* type-specific free operations */
      case BGP_MP_REACH_NLRI:
        break; /* freed below with mrt_free_nlri() */
      default: /* simple free */
        if (attributes->attr[i].unknown)
          free(attributes->attr[i].unknown);
    };
  }
  if (attributes->mp_reach_nlri) {
    mrt_free_nlri(&(attributes->mp_reach_nlri->l), TRUE);
    free(attributes->mp_reach_nlri);
  }
  if (attributes->trace) free(attributes->trace);
  free(attributes);
  return;
}

static const char *mrt_attribute_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section\n"
"[uint8 flags][uint8 type][uint8 or uint16 length (extended length flag)]\n"
"[0 or more bytes attribute data]";


static const char *mrt_atomic_aggregate_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (f) ATOMIC_AGGREGATE\n"
"No data. Simple flag: attribute exists or it does not.";

void mrt_attribute_atomic_aggregate (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  if (attributes->atomic_aggregate) {
    snprintf(error, 99, "duplicate ATOMIC_AGGREGATE attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  if (attribute->after - attribute->content > 0) {
    snprintf(error, 99, 
        "invalid ATOMIC AGGREGATE attribute length expecting 0 got %u bytes",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_atomic_aggregate_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->length8);
    attribute->trace->error_afterbyte = attribute->content;
    attribute->fault = TRUE;
    return;
  }
  attributes->atomic_aggregate = TRUE;
  return;
}

static const char *mrt_mp_reach_information = 
"https://datatracker.ietf.org/doc/html/rfc4760#section-3\n"
"[uint16 address family][uint8 SAFI (unicast/multicast)]\n"
"[uint8 byte length of next hop addresses][next hop addresses]\n"
"[uint8 zero (reserved)][nlri information until the end of the buffer]\n"
"Next Hop: https://datatracker.ietf.org/doc/html/rfc2545#section-3\n"
"NLRI: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Network Layer Reachability Information\n"
"[uint8 prefix length][0 or more bytes, minimum needed for the prefix len]\n"
"e.g. /0 needs 0 bytes, /60 needs 8, /128 needs 16.";

void mrt_attribute_mp_reach_nlri (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  struct BGP_MP_REACH_HEADER *h;
  size_t minsize;
  uint8_t badflag = FALSE;
  struct BGP_MP_REACH *reach;

  if (attributes->mp_reach_nlri) {
    snprintf(error, 99, "duplicate MP_REACH_NLRI attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  minsize = sizeof(struct BGP_MP_REACH_HEADER) + 5;
  h = (struct BGP_MP_REACH_HEADER*) attribute->content;
  if ((attribute->after - attribute->content) < minsize) badflag=TRUE;
  else {
    minsize = sizeof(struct BGP_MP_REACH_HEADER) + h->next_hop_len + 1;
    if ((attribute->after - attribute->content) < minsize) badflag=TRUE;
  }
  if (badflag) {
    snprintf(error, 99, 
        "short MP_REACH_NRLI attribute %u bytes of minimum %u",
        (unsigned int) (attribute->after - attribute->content),
        (unsigned int) minsize);
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_mp_reach_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->length8);
    attribute->trace->error_afterbyte = attribute->content;
    attribute->trace->overflow_firstbyte = attribute->after;
    attribute->trace->overflow_afterbyte = attribute->content + minsize;
    attribute->fault = TRUE;
    return ;
  }
  switch (h->address_family) {
    case BGP4MP_AFI_IPV4:
      if (h->next_hop_len != 4) badflag = TRUE;
      break;
    case BGP4MP_AFI_IPV6:
      if ((h->next_hop_len != 16) && (h->next_hop_len != 32)) badflag = TRUE;
      break;
    default:
      snprintf(error, 99, "MP_REACH_NLRI address family %x unknown",
        ntohl(h->address_family));
      error[99]=0;
      attribute->trace = 
        newtraceback(record, error, mrt_attribute_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = attribute->after;
      attribute->trace->error_firstbyte = (uint8_t*) &(h->address_family);
      attribute->trace->error_afterbyte = attribute->trace->error_firstbyte+2;
      attribute->fault = TRUE;
      return;
  };
  if (badflag) { /* wrong next hop length */
    snprintf(error, 99, 
        "MP_REACH_NRLI next hop length expecting %s bytes got %u",
        (h->address_family == BGP4MP_AFI_IPV6)?"16 or 32":"4",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_mp_reach_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(h->next_hop_len);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return ;
  }
  /* malloc a buffer for BGP_MP_REACH and populate the reach->l structure
   * with the decoded and traced NRLI information */
  reach = (struct BGP_MP_REACH*) mrt_nlri_deserialize (record,
    attribute->content + minsize, attribute->after,
    &(attribute->header->length16), h->address_family, TRUE, 
    ((uint8_t*) &(reach->l)) - ((uint8_t*) reach));
  if (reach->l.faults) {
    snprintf(error, 99, "MP_REACH_NRLI decode fault: %s",
        (reach->l.error)?reach->l.error->error:"");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_mp_reach_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->content + minsize;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
  }
  reach->header = h;
  reach->attribute = attribute;
  reach->address_family = h->address_family;
  reach->safi = h->subsequent_address_family;
  switch (h->address_family) {
    case BGP4MP_AFI_IPV4:
      reach->next_hop = *((struct ipv4_address*) (h->next_hop));
      break;
    case BGP4MP_AFI_IPV6:
      reach->global_next_hop = *((struct ipv6_address*) (h->next_hop));
      if (h->next_hop_len == 32)
        reach->local_next_hop = *((struct ipv6_address*) (h->next_hop + 16));
      break;
    default: /* unreachable */
  }
  attribute->mp_reach_nlri = reach;
  attributes->mp_reach_nlri = reach;
  return ;
}

static const char *mrt_aggregator4_information = 
"https://datatracker.ietf.org/doc/html/rfc6793#section-3\n"
"[uint32 AS Number][uint32 IP Address]";

void mrt_attribute_aggregator4 (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  struct ipv4_address ip;

  if (attributes->aggregator_as) {
    snprintf(error, 99, "duplicate AS4_AGGREGATOR attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  if (attribute->after - attribute->content != 8) {
    snprintf(error, 99, 
        "invalid AS4_AGGREGATOR attribute length expecting 8 bytes got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_aggregator4_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    if (attribute->after - attribute->content < 4) {
      attribute->trace->overflow_firstbyte = attribute->after;
      attribute->trace->overflow_afterbyte = attribute->content + 4;
    }
    attribute->fault = TRUE;
    return ;
  }
  ip = *((struct ipv4_address*) (attribute->content + 4));
  if ( (attributes->aggregator.whole != 0) &&
       (attributes->aggregator.whole != ip.whole)) {
    snprintf(error, 99, 
        "AS4_AGGREGATOR and AGGREGATOR IP address mismatch: " PRI_IPV4
        " != " PRI_IPV4,
        PRI_IPV4_V(ip), PRI_IPV4_V((attributes->aggregator)));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_aggregator4_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->content + 2;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }

  attributes->aggregator_as = ntohl(*((uint32_t*) attribute->content));
  attributes->aggregator = ip;
  return ;
}

static const char *mrt_aggregator2_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section\n"
"[uint8 flags][uint8 type][uint8 or uint16 length (extended length flag)]\n"
"[0 or more bytes attribute data]\n"
"Path Attributes section, part (g) AGGREGATOR\n"
"[uint16 or uint32 AS Number][uint32 IP Address]\n"
"https://datatracker.ietf.org/doc/html/rfc6793#section-3\n"
"Will be a 4-byte AS number between 'new' BGP speakers.";

void mrt_attribute_aggregator2 (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  struct ipv4_address ip;
  size_t length;

  if (attributes->aggregator_as) {
    snprintf(error, 99, "duplicate AGGREGATOR attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  length = attribute->after - attribute->content;
  if ((length != 6) && (length != 8)) {
    snprintf(error, 99, 
        "invalid AGGREGATOR attribute length expecting 6 or 8 bytes got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_aggregator2_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->length8);
    attribute->trace->error_afterbyte = attribute->content;
    if (attribute->after - attribute->content < 4) {
      attribute->trace->overflow_firstbyte = attribute->after;
      attribute->trace->overflow_afterbyte = attribute->content + 4;
    }
    attribute->fault = TRUE;
    return ;
  }
  ip = *((struct ipv4_address*) (attribute->content + 2));
  if (length == 8) 
    ip = *((struct ipv4_address*) (attribute->content + 4));
  if ( (attributes->aggregator.whole != 0) &&
       (attributes->aggregator.whole != ip.whole)) {
    snprintf(error, 99, 
        "AGGREGATOR and AS4_AGGREGATOR IP address mismatch: " PRI_IPV4
        " != " PRI_IPV4,
        PRI_IPV4_V(ip), PRI_IPV4_V((attributes->aggregator)));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_aggregator2_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->content + 2;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }

  if (length == 6) attributes->aggregator_as = 
    (uint32_t) ntohs(*((uint16_t*) attribute->content));
  else attributes->aggregator_as = ntohl(*((uint32_t*) attribute->content));
  attributes->aggregator = ip;
  return ;
}

static const char *mrt_next_hop_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (c) NEXT_HOP\n"
"[uint32 IP Address]";

void mrt_attribute_next_hop (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];

  if (attributes->next_hop_set) {
    snprintf(error, 99, "duplicate NEXT_HOP attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  if (attribute->after - attribute->content != 4) {
    snprintf(error, 99, 
        "invalid NEXT_HOP attribute length expecting 4 bytes got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_next_hop_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    if (attribute->after - attribute->content < 4) {
      attribute->trace->overflow_firstbyte = attribute->after;
      attribute->trace->overflow_afterbyte = attribute->content + 4;
    }
    attribute->fault = TRUE;
    return ;
  }
  attributes->next_hop_set = TRUE;
  attributes->next_hop = *((struct ipv4_address*) attribute->content);
  return ;
}

static const char *mrt_local_pref_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (e) LOCAL_PREF\n"
"[uint32 local pref] larger = more preferred";

void mrt_attribute_local_pref (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];

  if (attributes->local_pref_set) {
    snprintf(error, 99, "duplicate LOCAL_PREF attribute");
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = &(attribute->header->type);
    attribute->trace->error_afterbyte = attribute->trace->error_firstbyte + 1;
    attribute->fault = TRUE;
    return;
  }
  if (attribute->after - attribute->content != 4) {
    snprintf(error, 99, 
        "invalid LOCAL_PREF attribute length expecting 4 bytes got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_local_pref_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    if (attribute->after - attribute->content < 4) {
      attribute->trace->overflow_firstbyte = attribute->after;
      attribute->trace->overflow_afterbyte = attribute->content + 4;
    }
    attribute->fault = TRUE;
    return ;
  }
  attributes->local_pref_set = TRUE;
  attributes->local_pref = ntohl( (*((uint32_t*) attribute->content)) );
  return ;
}

static const char *mrt_origin_attribute_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (a) ORIGIN\n"
"[uint8 origin] 0=IGP, 1=EGP, 2=INCOMPLETE";

void mrt_attribute_origin (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  uint8_t origin;
  char error[100];

  if (attribute->after - attribute->content > 0) {
    origin = *(attribute->content);
    if (origin > 2) {
      snprintf(error, 99, 
        "invalid BGP ORIGIN %u in attribute of %svalid size %u",
        (unsigned int) origin,
        (attribute->after - attribute->content == 1)?"":"IN",
        (unsigned int) (attribute->after - attribute->content));
      error[99]=0;
      attribute->trace = 
        newtraceback(record, error, mrt_origin_attribute_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
      attribute->trace->error_firstbyte = attribute->trace->firstbyte;
      attribute->trace->error_afterbyte = attribute->after;
      attribute->fault = TRUE;
      return ;
    }
    if (attributes->origin != BGP_ORIGIN_UNSET) {
      snprintf(error, 99, 
        "duplicate BGP ORIGIN %u", (unsigned int) origin);
      error[99]=0;
      attribute->trace = 
        newtraceback(record, error, mrt_origin_attribute_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = attribute->after;
      attribute->trace->error_firstbyte = attribute->trace->firstbyte;
      attribute->trace->error_afterbyte = attribute->after;
      attribute->fault = TRUE;
      return ;
    }
    attributes->origin = origin;
  }
  if (attribute->after - attribute->content != 1) {
    snprintf(error, 99, 
        "invalid BGP ORIGIN attribute length expecting 1 byte got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace = 
      newtraceback(record, error, mrt_origin_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  return;
}

static const char *mrt_path_attribute_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (b) AS_PATH\n"
"[path segment][path segment][...] where a path segment is\n"
"[uint8 type][uint8 number of ASes in segment][N x uint16 number of ASes]\n"
"  ...or... \n"
"https://datatracker.ietf.org/doc/html/rfc6793#section-3\n"
"[path segment][path segment][...] where a path segment is\n"
"[uint8 type][uint8 number of ASes in segment][N x uint32 number of ASes]\n"
"";

uint8_t mrt_check_as_path_four_bytes(struct BGP_ATTRIBUTE *attribute) {
/* Check if the attribute contains an AS_PATH using 4-byte AS numbers.
 * If it decodes to exactly the number of bytes in the buffer then yes.
 * Otherwise no.
 */
  uint8_t *p = attribute->content;
  struct BGP_AS_PATH_SEGMENT *segment;
  size_t bytes;

  while (attribute->after - p >= 2) {
    segment = (struct BGP_AS_PATH_SEGMENT*) p;
    if ((segment->type != BGP_AS_SET) && (segment->type != BGP_AS_SEQUENCE))
      return 0;
    bytes = 4 * ((size_t) segment->ascount);
    p += sizeof(struct BGP_AS_PATH_SEGMENT) + bytes;
  }
  if (p > attribute->after) return 0;

  return 1;
}

void mrt_attribute_path (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
, uint8_t fourbyteas
) {
  char error[100];

  if (!fourbyteas) fourbyteas = mrt_check_as_path_four_bytes(attribute);
 
  // remove remaining stuff when function is complete 
  // it's just there to make the warnings go away
  error[0]=mrt_path_attribute_information[0];
  error[1]=error[0];
  return;
}

static const char *mrt_update_information =
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Update message format\n"
"[uint16 byte length of withdrawn routes section]\n"
"[0 or more bytes, withdrawn routes in NLRI prefix format]\n"
"[uint16 byte length of BGP attributes such as communities]\n"
"[0 or more bytes, BGP attributes]\n"
"[0 or more bytes, new/updated routes in NLRI prefix format]\n"
"The new/updated routes section starts after the BGP attributes (position\n"
"determined by the uint16 attributes byte length) and continues until the\n"
"end of the BGP update message (which is also the end of the MRT record).";

struct BGP_ATTRIBUTES *mrt_extract_attributes (
  struct MRT_RECORD *record
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t address_family
) {
  uint8_t *lengthsource = firstbyte - 2;
  struct BGP_ATTRIBUTES *attributes;
  struct BGP_ATTRIBUTE *attribute;
  int count, i, badflag;
  size_t structsize;
  uint8_t *p;
  char error[200];
  uint16_t length;

  count = mrt_count_attributes(firstbyte, afterbyte);
  structsize = sizeof(struct BGP_ATTRIBUTES) + 
    (sizeof(struct BGP_ATTRIBUTE) * (count + 1));
  attributes = (struct BGP_ATTRIBUTES*) malloc (structsize);
  assert (attributes != NULL);
  memset (attributes, 0, structsize);
  attributes->numattributes = count;
  attributes->origin = BGP_ORIGIN_UNSET;
  for (i=0, p=firstbyte; p < afterbyte; i++) {
    attribute = &(attributes->attr[i]);
    attribute->header = (struct BGP_ATTRIBUTE_HEADER *) p;
    badflag = FALSE;
    if ((afterbyte - p) < (sizeof(struct BGP_ATTRIBUTE_HEADER)-1))
      badflag = TRUE;
    if (!badflag) {
      if ( (attribute->header->extended_length) && 
         ((afterbyte - p) < sizeof(struct BGP_ATTRIBUTE_HEADER)) )
        badflag = TRUE;
    }
    if (badflag) {
      snprintf(error, 199, 
          "attribute header %lu bytes but only %u available",
          sizeof(struct BGP_ATTRIBUTE_HEADER), 
          (unsigned int) (afterbyte - p) );
      error[199]=0;
      attribute->trace = 
        newtraceback(record, error, mrt_update_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = afterbyte;
      attribute->trace->error_firstbyte = lengthsource;
      attribute->trace->error_afterbyte = firstbyte; /* of all attributes */
      attribute->trace->overflow_firstbyte = afterbyte;
      attribute->trace->overflow_afterbyte = attribute->trace->firstbyte +
          sizeof(struct BGP_ATTRIBUTE_HEADER);
      attribute->fault = TRUE;
      attributes->fault = TRUE;
      break;
    }
    attribute->type = attribute->header->type;
    if (attribute->header->extended_length) {
      p += sizeof(struct BGP_ATTRIBUTE_HEADER);
      length = ntohs(attribute->header->length16);
    } else {
      p += sizeof(struct BGP_ATTRIBUTE_HEADER) - 1;
      length = (uint16_t) attribute->header->length8;
    }
    attribute->content = p;
    attribute->after = attribute->content + length;
    if (attribute->after > afterbyte) {
      snprintf(error, 199, 
        "attribute length %u+%u bytes but only %u available",
        (unsigned int) (p - ((uint8_t*) attribute->header)),
        (unsigned int) length, 
        (unsigned int) (afterbyte - ((uint8_t*) attribute->header)) );
      error[199]=0;
      attribute->trace = 
        newtraceback(record, error, mrt_attribute_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = afterbyte;
      attribute->trace->error_firstbyte = &(attribute->header->length8);
      attribute->trace->error_afterbyte = attribute->content;
      attribute->trace->overflow_firstbyte = afterbyte;
      attribute->trace->overflow_afterbyte = attribute->after;
      attribute->fault = TRUE;
      attributes->fault = TRUE;
      break;
    }

    switch (attribute->type) {
      case BGP_ORIGIN:
        mrt_attribute_origin(record, attributes, attribute);
        break;
      case BGP_AS_PATH:
        break;
      case BGP_NEXT_HOP:
        mrt_attribute_next_hop(record, attributes, attribute);
        break;
      case BGP_MED:
        break;
      case BGP_LOCAL_PREF:
        mrt_attribute_local_pref(record, attributes, attribute);
        break;
      case BGP_ATOMIC_AGGREGATE:
        mrt_attribute_atomic_aggregate(record, attributes, attribute);
        break;
      case BGP_AGGREGATOR:
        mrt_attribute_aggregator2(record, attributes, attribute);
        break;
      case BGP_AS4_AGGREGATOR:
        mrt_attribute_aggregator4(record, attributes, attribute);
        break;
      case BGP_MP_REACH_NLRI:
        mrt_attribute_mp_reach_nlri(record, attributes, attribute);
        break;
      default:
    };
    p = attribute->after;
    if (! attribute->trace) {
      attribute->trace = newtraceback(record, NULL, mrt_attribute_information);
      attribute->trace->firstbyte = (uint8_t*) attribute->header;
      attribute->trace->afterbyte = p;
    }
  }
  if (attributes->fault) { /* buffer overflow */
    snprintf(error, 199, "attributes overflowed buffer length %u",
        (unsigned int) (afterbyte - firstbyte));
    error[199]=0;
    attributes->trace = 
      newtraceback(record, error, mrt_update_information);
    attributes->trace->firstbyte = firstbyte;
    attributes->trace->afterbyte = afterbyte;
    attributes->trace->error_firstbyte = lengthsource;
    attributes->trace->error_afterbyte = firstbyte;
  } else {
    attributes->trace = newtraceback(record, NULL, mrt_update_information);
    attributes->trace->firstbyte = firstbyte;
    attributes->trace->afterbyte = afterbyte;
  }

  /* sort here */

  return attributes;
}


static const char *mrt_nlri_information = 
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Network Layer Reachability Information\n"
"[uint8 prefix length][0 or more bytes, minimum needed for the prefix len]\n"
"e.g. /0 needs 0 bytes, /15 needs 2, /17 needs 3, /24 needs 3, /25 needs 4.";

uint8_t *mrt_nlri_consume_one (
  struct MRT_RECORD *record
, struct NLRI *nlri
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t *attribute_length
, uint16_t address_family
) {
  uint8_t prefix_bytes;
  char error[200];
  struct ipv4_address netv4;
  struct ipv6_address netv6;

  if (firstbyte >= afterbyte) return NULL; /* end of list */
  nlri->address_family = address_family;
  nlri->prefix_len = *((uint8_t*) firstbyte);
  prefix_bytes = (nlri->prefix_len >> 3) + ((nlri->prefix_len & 0x7)?1:0);
  if ((firstbyte + prefix_bytes + 1) > afterbyte) {
    /* routing prefix would overflow the available buffer */
    nlri->fault_flag = TRUE;
    snprintf (error, 199, 
      "nlri prefix length %u requires %u bytes but only has %u",
      (unsigned int) nlri->prefix_len, (unsigned int) prefix_bytes,
      (unsigned int) (afterbyte - firstbyte - 1));
    error[199]=0;
    nlri->trace = newtraceback(record, error, mrt_nlri_information);
    nlri->trace->firstbyte = firstbyte + 1;
    nlri->trace->afterbyte = afterbyte;
    nlri->trace->error_firstbyte = firstbyte;
    nlri->trace->error_afterbyte = nlri->trace->firstbyte;
    nlri->trace->overflow_firstbyte = afterbyte;
    nlri->trace->overflow_afterbyte = nlri->trace->firstbyte + prefix_bytes;
  
    return firstbyte + prefix_bytes + 1;
  }
  /* sanity-check prefix length */
  switch (address_family) {
    case BGP4MP_AFI_IPV4:
      if (nlri->prefix_len <= 32) break;
    case BGP4MP_AFI_IPV6:
      if (nlri->prefix_len <= 128) break;
      /* insane netmask */
      nlri->fault_flag = TRUE;
      snprintf (error, 199, 
        "nlri prefix length %u too long for address family %s",
        (unsigned int) nlri->prefix_len, 
        (address_family==BGP4MP_AFI_IPV4)?"IPv4":"IPv6");
      error[199]=0;
      nlri->trace = newtraceback(record, error, mrt_nlri_information);
      nlri->trace->firstbyte = firstbyte + 1;
      nlri->trace->afterbyte = nlri->trace->firstbyte + prefix_bytes;
      nlri->trace->error_firstbyte = firstbyte;
      nlri->trace->error_afterbyte = nlri->trace->firstbyte;
      return firstbyte + prefix_bytes + 1;
    default:
      /* unknown address family */
      nlri->fault_flag = TRUE;
      snprintf (error, 199, 
        "nlri unknown address family 0x%x with prefix of length %u",
        (unsigned int) address_family,
        (unsigned int) nlri->prefix_len); 
      error[199]=0;
      nlri->trace = newtraceback(record, error, NULL);
      nlri->trace->firstbyte = firstbyte;
      nlri->trace->afterbyte = nlri->trace->firstbyte + prefix_bytes + 1;
      nlri->trace->error_firstbyte = nlri->trace->firstbyte;
      nlri->trace->error_afterbyte = nlri->trace->afterbyte;
      return firstbyte + prefix_bytes + 1;
  };
  switch (address_family) {
    case BGP4MP_AFI_IPV4:
      memset(&(nlri->ipv4), 0, sizeof(nlri->ipv4));
      memcpy(&(nlri->ipv4), firstbyte + 1, prefix_bytes);
      netv4 = ipv4_apply_netmask(nlri->ipv4, nlri->prefix_len);
      if (memcmp(&(nlri->ipv4), &netv4, sizeof(netv4)) != 0) {
        /* Prefix does not match prefix length */
        nlri->fault_flag = TRUE;
        snprintf (error, 199, 
          "nlri IPv4 prefix " PRI_IPV4 "/%u wrong. " PRI_IPV4 " is "
          "correct for /%u",
          PRI_IPV4_V(nlri->ipv4), (unsigned int) nlri->prefix_len,
          PRI_IPV4_V(netv4), (unsigned int) nlri->prefix_len); 
        error[199]=0;
        nlri->trace = newtraceback(record, error, NULL);
        nlri->trace->firstbyte = firstbyte;
        nlri->trace->afterbyte = nlri->trace->firstbyte + prefix_bytes + 1;
        nlri->trace->error_firstbyte = nlri->trace->firstbyte + 1;
        nlri->trace->error_afterbyte = nlri->trace->afterbyte;
      }      
      break;
    case BGP4MP_AFI_IPV6:
      memset(&(nlri->ipv6), 0, sizeof(nlri->ipv6));
      memcpy(&(nlri->ipv6), firstbyte + 1, prefix_bytes);
      netv6 = ipv6_apply_netmask(nlri->ipv6, nlri->prefix_len);
      if (memcmp(&(nlri->ipv6), &netv6, sizeof(netv6)) != 0) {
        /* Prefix does not match prefix length */
        snprintf (error, 199, 
          "nlri IPv6 prefix " PRI_IPV6 "/%u wrong. " PRI_IPV6 " is "
          "correct for /%u",
          PRI_IPV6_V(nlri->ipv6), (unsigned int) nlri->prefix_len,
          PRI_IPV6_V(netv6), (unsigned int) nlri->prefix_len); 
        error[199]=0;
        nlri->trace = newtraceback(record, error, NULL);
        nlri->trace->firstbyte = firstbyte;
        nlri->trace->afterbyte = nlri->trace->firstbyte + prefix_bytes + 1;
        nlri->trace->error_firstbyte = nlri->trace->firstbyte + 1;
        nlri->trace->error_afterbyte = nlri->trace->afterbyte;
        nlri->fault_flag = TRUE;
      }      
      break;
    default: /* not reachable */
  }

  if (!nlri->trace) {
    nlri->trace = newtraceback(record, NULL, mrt_nlri_information);
    nlri->trace->firstbyte = firstbyte;
    nlri->trace->afterbyte = firstbyte + prefix_bytes + 1;
  }
  
  return nlri->trace->afterbyte;
}

void mrt_free_nlri (
  struct NLRI_LIST *list
, uint8_t embedded
) {
  int i;

  if (!list) return;
  for (i=0; i<list->num_nlri; i++) {
    if (list->prefixes[i].trace) free(list->prefixes[i].trace);
  }
  if (list->error) free(list->error);
  if (!embedded) free(list);
  return;
}

struct NLRI_LIST *mrt_nlri_deserialize (
  struct MRT_RECORD *record
, uint8_t *firstbyte
, uint8_t *afterbyte
, uint16_t *length  /* location of bytes setting length for error reporting */
, uint16_t address_family
, uint8_t from_attribute_flag /* FALSE if from the outer UPDATE message */
, size_t prefix_bytes /* add this number of bytes before return */
) {
  struct NLRI_LIST *list;
  struct NLRI *nlri;
  int numnlri = 0;
  int faults = 0;
  uint8_t *next;
  uint8_t *buffer;
  size_t bufsize;

  nlri = (struct NLRI*) malloc (sizeof(struct NLRI) * (afterbyte-firstbyte));
  assert(nlri != NULL);
  memset(nlri, 0, sizeof(struct NLRI) * (afterbyte-firstbyte));
  for (next=firstbyte; next && (next < afterbyte); numnlri++) {
    next = mrt_nlri_consume_one (record, &(nlri[numnlri]), next, afterbyte,
             length, address_family);
    if (nlri[numnlri].fault_flag) faults ++;
  }

  bufsize = prefix_bytes + sizeof(struct NLRI_LIST) +
    (sizeof(struct NLRI) * numnlri);
  buffer = (uint8_t*) malloc(bufsize);
  assert(buffer != NULL);
  memset(buffer, 0, sizeof(struct NLRI_LIST) + prefix_bytes);
  list = (struct NLRI_LIST*) (buffer + prefix_bytes);
  memcpy(list->prefixes, nlri, sizeof(struct NLRI) * numnlri);
  free(nlri);
  list->num_nlri = numnlri;
  list->faults = faults;
  if (next > afterbyte) {
    /* overran buffer deserializing prefixes */
    char error[200];
    snprintf (error, 199,
        "nlri buffer of %u bytes did not align with the encoded prefixes",
        (unsigned int) (afterbyte - firstbyte));
    error[199]=0;
    list->error = newtraceback(record, error, (from_attribute_flag)?
      mrt_nlri_information:mrt_update_information );
    list->error->firstbyte = firstbyte;
    list->error->afterbyte = afterbyte;
    list->error->error_firstbyte = (uint8_t*) length;
    list->error->error_afterbyte = 
      list->error->error_firstbyte + sizeof(uint16_t);
  }
  return (struct NLRI_LIST*) buffer;
}

void mrt_free_bgp4mp_message (struct BGP4MP_MESSAGE *m) {
  if (!m) return;
  if (m->error) free(m->error);
  if (m->trace_as) free(m->trace_as);
  if (m->trace_peerip) free(m->trace_peerip);
  if (m->withdrawals) mrt_free_nlri(m->withdrawals, FALSE);
  if (m->nlri) mrt_free_nlri(m->nlri, FALSE);
  if (m->attributes) mrt_free_attributes(m->attributes);
  free(m);
  return;
}

static const char *mrt_bgp_update_information =
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.1\n"
"[16 byte 0xff marker][uint16 length][uint8 type=update]\n"
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"[uint16 byte length of withdrawn routes section]\n"
"[0 or more bytes, withdrawn routes in NLRI prefix format]\n"
"[uint16 byte length of BGP attributes such as communities]\n"
"[0 or more bytes, BGP attributes]\n"
"[0 or more bytes, new/updated routes in NLRI prefix format]\n"
"The new/updated routes section starts after the BGP attributes (position\n"
"determined by the uint16 attributes byte length) and continues until the\n"
"end of the BGP update message (which is also the end of the MRT record).";

static const char *mrt_bgp4mp_message_information =
"https://datatracker.ietf.org/doc/html/rfc6396#section-4.4.2\n"
"[uint16 peer AS][uint16 local AS][uint16 interface index]\n"
"[uint16 address family][4 or 16 bytes peer IP address]\n"
"[4 or 16 bytes local IP address][BGP UPDATE message]";

static const char *mrt_bgp4mp_message_as4_information =
"https://datatracker.ietf.org/doc/html/rfc6396#section-4.4.3\n"
"[uint32 peer AS][uint32 local AS][uint16 interface index]\n"
"[uint16 address family][4 or 16 bytes peer IP address]\n"
"[4 or 16 bytes local IP address][BGP UPDATE message]";


struct BGP4MP_MESSAGE *mrt_deserialize_bgp4mp_message(
/* record->mrt->type == MRT_BGP4MP or MRT_BGP4MP_ET
 * record->mrt->subtype == BGP4MP_MESSAGE or BGP4MP_MESSAGE_AS4
 * deserialize the BGP UPDATE message between record->mrt_message and
 * record->aftermrt */
  struct MRT_RECORD *record
) {
  char error[200];
  struct BGP4MP_MESSAGE *m; /* deserialized message */
  size_t message_length, min_length;

  m = (struct BGP4MP_MESSAGE*) malloc (sizeof(*m));
  assert(m != NULL);
  memset(m, 0, sizeof(*m));

  /* first make sure we have enough bytes to begin parsing a BGP4MP_MESSAGE */
  message_length = record->aftermrt - record->mrt_message;
  min_length = 16 + sizeof(struct BGP_UPDATE_MESSAGE) + 2;
  if (record->mrt->subtype == BGP4MP_MESSAGE_AS4) min_length += 4;
  if (message_length < min_length) {
    snprintf (error, 199,
        "deserialize_bgp4mp %s message size %lu shorter than minimum %lu",
        (record->mrt->subtype == BGP4MP_MESSAGE)?"BGP4MP_MESSAGE":
         "BGP4MP_MESSAGE_AS4", message_length, min_length);
    error[199]=0;
    m->error = newtraceback(record, error,
      (record->mrt->subtype == BGP4MP_MESSAGE)?
       mrt_bgp4mp_message_information:mrt_bgp4mp_message_as4_information);
    m->error->firstbyte = record->mrt_message;
    m->error->afterbyte = record->aftermrt;
    m->error->overflow_firstbyte = record->aftermrt;
    m->error->overflow_afterbyte = record->mrt_message + min_length;
    m->error->error_firstbyte = (uint8_t*) &(record->mrt->length);
    m->error->error_afterbyte = record->mrt->message;
    return m;
  }

  /* next, capture the AS numbers and figure out where to start looking
   * for the router IP addresses */
  m->bgp4mp = (struct BGP4MP_MESSAGE_HEADER*) record->mrt_message;
  m->nlri_afterbyte = record->aftermrt;
  if (record->mrt->subtype == BGP4MP_MESSAGE)  {
    m->peeras = (uint32_t) ntohs(m->bgp4mp->peeras2);
    m->localas = (uint32_t) ntohs(m->bgp4mp->localas2);
    m->header = &(m->bgp4mp->head2);
    m->trace_as = newtraceback(record, NULL, mrt_bgp4mp_message_information);
    m->trace_as->firstbyte = (uint8_t*) m->bgp4mp;
    m->trace_as->afterbyte = (uint8_t*) m->header;
  } else { /* BGP4MP_MESSAGE_AS4 */
    m->peeras = ntohl(m->bgp4mp->peeras4);
    m->localas = ntohl(m->bgp4mp->localas4);
    m->header = &(m->bgp4mp->head4);
    m->trace_as = newtraceback(record, NULL, 
                    mrt_bgp4mp_message_as4_information);
    m->trace_as->firstbyte = (uint8_t*) m->bgp4mp;
    m->trace_as->afterbyte = (uint8_t*) m->header;
  }

  /* next, capture the router IP addresses. */
  m->peer_ipv4 = &(m->header->peer4); /* pointer magic also sets peer_ipv6 */
  switch (m->header->address_family) {
    case BGP4MP_AFI_IPV6:
      /* message bigger than the IPv4 minimum, recheck that we have enough
       * bytes. */
      min_length += 24;
      if (message_length < min_length) {
        snprintf (error, 199, "deserialize_bgp4mp %s IPv6 message "
          "size %lu shorter than minimum %lu",
          (record->mrt->subtype == BGP4MP_MESSAGE)?"BGP4MP_MESSAGE":
           "BGP4MP_MESSAGE_AS4", message_length, min_length);
        error[199]=0;
        m->error = newtraceback(record, error,
          (record->mrt->subtype == BGP4MP_MESSAGE)?
          mrt_bgp4mp_message_information:mrt_bgp4mp_message_as4_information);
        m->error->firstbyte = record->mrt_message;
        m->error->afterbyte = record->aftermrt;
        m->error->overflow_firstbyte = record->aftermrt;
        m->error->overflow_afterbyte = record->mrt_message + min_length;
        m->error->error_firstbyte = (uint8_t*) &(record->mrt->length);
        m->error->error_afterbyte = record->mrt->message;
        return m;
      }
      m->local_ipv6 = &(m->header->local6);
      m->bgp = m->header->bgp_message6;
      m->trace_peerip = newtraceback(record, NULL, 
         (record->mrt->subtype == BGP4MP_MESSAGE)?
         mrt_bgp4mp_message_information:mrt_bgp4mp_message_as4_information);
      m->trace_peerip->firstbyte = (uint8_t*) m->peer_ipv6;
      m->trace_peerip->afterbyte = (uint8_t*) m->bgp;
      break;
    case BGP4MP_AFI_IPV4:
      m->local_ipv4 = &(m->header->local4);
      m->bgp = m->header->bgp_message4;
      m->trace_peerip = newtraceback(record, NULL, 
         (record->mrt->subtype == BGP4MP_MESSAGE)?
         mrt_bgp4mp_message_information:mrt_bgp4mp_message_as4_information);
      m->trace_peerip->firstbyte = (uint8_t*) m->peer_ipv4;
      m->trace_peerip->afterbyte = (uint8_t*) m->bgp;
      break;
    default: /* unknown address family, not IPv4 or IPv6. Abort. */
      snprintf (error, 199, "deserialize_bgp4mp unknown address family %x",
        (unsigned int) ntohs(m->header->address_family));
      error[199]=0;
      m->error = newtraceback(record, error,
        (record->mrt->subtype == BGP4MP_MESSAGE)?
        mrt_bgp4mp_message_information:mrt_bgp4mp_message_as4_information);
      m->error->firstbyte = (uint8_t*) m->bgp4mp;
      m->error->afterbyte = record->aftermrt;
      m->error->error_firstbyte = (uint8_t*) &(m->header->address_family);
      m->error->error_afterbyte = m->error->error_firstbyte + 2;
      return m;
  };

  /* We're up to the actual BGP message embedded in the BGP4MP record */
  if (memcmp(m->bgp->marker, BGP_MESSAGE_MARKER,
             sizeof(BGP_MESSAGE_MARKER)) !=0 ) {
    snprintf (error, 199, "deserialize_bgp4mp bgp marker is not 0xff");
    error[199]=0;
    m->error = newtraceback(record, error, mrt_bgp_update_information);
    m->error->firstbyte = record->mrt_message;
    m->error->afterbyte = record->aftermrt;
    m->error->error_firstbyte = (uint8_t*) m->bgp->marker;
    m->error->error_afterbyte = m->error->error_firstbyte + 16;
    return m;
  }
  if (((uint8_t*)m->bgp) + ntohs(m->bgp->length) != record->aftermrt) {
    snprintf (error, 199, "deserialize_bgp4mp MRT-derived length %lu bytes"
      " != with BGP %u bytes",
      record->aftermrt - record->mrt_message, 
      (unsigned int) ntohs(m->bgp->length));
    error[199]=0;
    m->error = newtraceback(record, error, mrt_bgp_update_information);
    m->error->firstbyte = (uint8_t*) &(m->bgp->length);
    m->error->afterbyte = m->error->firstbyte + 2;
    m->error->error_firstbyte = (uint8_t*) &(record->mrt->length);
    m->error->error_afterbyte = record->mrt->message;
    return m;
  }
  if (m->bgp->type != 2) {
    snprintf (error, 199, "deserialize_bgp4mp BGP type %u is not update (2)",
      (unsigned int) m->bgp->type);
    error[199]=0;
    m->error = newtraceback(record, error, mrt_bgp_update_information);
    m->error->firstbyte = (uint8_t*) m->bgp;
    m->error->afterbyte = record->aftermrt;
    m->error->error_firstbyte = &(m->bgp->type);
    m->error->error_afterbyte = &(m->bgp->type) + 1;
    return m;
  }
  m->withdrawals_firstbyte = m->bgp->routes_and_attributes;
  m->withdrawals_afterbyte = /* pntr magic sets path_attributes_length too */
    m->withdrawals_firstbyte + ntohs(m->bgp->withdrawn_routes_length);
  m->path_attributes_firstbyte = m->withdrawals_afterbyte + 2;
  if (m->path_attributes_firstbyte > record->aftermrt) {
    snprintf (error, 199, "deserialize_bgp4mp malformed update withdrawal "
      "size %u overruns the end of the buffer",
      (unsigned int) ntohs(m->bgp->withdrawn_routes_length));
    error[199]=0;
    m->error = newtraceback(record, error, mrt_bgp_update_information);
    m->error->firstbyte = m->withdrawals_firstbyte;
    m->error->afterbyte = record->aftermrt;
    m->error->overflow_firstbyte = record->aftermrt;
    m->error->overflow_afterbyte = m->path_attributes_firstbyte;
    m->error->error_firstbyte = (uint8_t*) &(m->bgp->withdrawn_routes_length);
    m->error->error_afterbyte = (uint8_t*) 
      (&(m->bgp->withdrawn_routes_length) + 1);
    return m;
  }
  m->path_attributes_afterbyte = m->path_attributes_firstbyte +
     ntohs(*(m->path_attributes_length));
  if (m->path_attributes_afterbyte > record->aftermrt) {
    snprintf (error, 199, "deserialize_bgp4mp malformed update attributes "
      "size %u overruns the end of the buffer",
      (unsigned int) ntohs(*(m->path_attributes_length)));
    error[199]=0;
    m->error = newtraceback(record, error, mrt_bgp_update_information);
    m->error->firstbyte = m->path_attributes_firstbyte;
    m->error->afterbyte = record->aftermrt;
    m->error->overflow_firstbyte = record->aftermrt;
    m->error->overflow_afterbyte = m->path_attributes_afterbyte;
    m->error->error_firstbyte = (uint8_t*) m->path_attributes_length;
    m->error->error_afterbyte = m->path_attributes_firstbyte;
    return m;
  }
  /* We have a BGP update message whose core lengths make sense 
   * Next, deserialize the prefixes and attributes */
  m->withdrawals = mrt_nlri_deserialize(record,
    m->withdrawals_firstbyte, m->withdrawals_afterbyte, 
    &(m->bgp->withdrawn_routes_length),
    m->header->address_family, FALSE, 0);
  m->nlri = mrt_nlri_deserialize(record, m->nlri_firstbyte, m->nlri_afterbyte, 
    m->path_attributes_length, m->header->address_family, FALSE, 0);
  m->attributes = mrt_extract_attributes(record, m->path_attributes_firstbyte,
    m->path_attributes_afterbyte, m->header->address_family);

  /* inner errors in those sections are not outer errors, so we're done. */
  return m;
}

static const char *mrt_extended_format = 
"https://datatracker.ietf.org/doc/html/rfc6396#section-3\n"
"[uint32 timestamp][uint16 message type][uint16 subtype]\n"
"[uint32 length in bytes][uint32 microseconds][record of length-4 bytes]";

uint8_t *mrt_extended_header_process(struct MRT_RECORD *record)
/* If an extended MRT header is present, process the microsecond timestamp.
 * Either way, return the start of the MRT message contained in the
 * record. Return NULL on error (record is too short).
 */
{
  struct MRT_TRACEBACK *trace = NULL;

  /* "extended" header is present if the MRT type is one of the known
   * extended header types. An extended header just means that there's
   * a 32 bit microsecond timestamp value between the regular header
   * and the message contained in the record.
   * Set mrt_message to the correct starting point (after either the
   * regular or extended header), set microseconds to the extended header
   * microseconds value (or zero if there is no extended header), and
   * set up the trace_microseconds structure to point to the information
   * that told us this was an extended header.
   */

  record->mrt_message = record->mrt->message;
  record->microseconds = 0;
  switch (record->mrt->type) {
    case MRT_BGP4MP_ET:
    case MRT_ISIS_ET:
    case MRT_OSPFv3_ET:
      if (record->extended->message > record->aftermrt) {
        /* error: extended header overflows the buffer */
        char error[200];

        snprintf (error, 199, 
            "%u: short extended header type %d/%d (%u bytes)\n",
            (unsigned int) record->seconds,
            (int) ntohs(record->mrt->type),
            (int) ntohs(record->mrt->subtype),
            (unsigned int) (record->aftermrt - ((uint8_t*) record->mrt))
            );
        error[199]=0;
        trace = newtraceback(record, error, mrt_extended_format);
        record->trace_microseconds = trace;
        trace->firstbyte = 
          (uint8_t*) &(record->extended->microsecond_timestamp);
        trace->afterbyte = record->aftermrt;
        trace->overflow_firstbyte = trace->afterbyte;
        trace->overflow_afterbyte = record->extended->message;
        trace->error_firstbyte = (uint8_t*) &(record->mrt->type);
        trace->error_afterbyte = 
          trace->error_firstbyte + sizeof(record->mrt->type);
        return NULL;
      }
      /* extended header is present */
      trace = newtraceback(record, NULL, mrt_extended_format);
      record->trace_microseconds = trace;
      trace->firstbyte = 
        (uint8_t*) &(record->extended->microsecond_timestamp);
      trace->afterbyte = record->extended->message;
      record->mrt_message = record->extended->message;
      record->microseconds = ntohl(record->extended->microsecond_timestamp);
      record->extended_flag = TRUE;
      break;
    default:
      /* regular header (not extended) */
      /* keep the data set prior to the switch() */
  };
  return record->mrt_message;
}

static const char *mrt_overall_format = 
"https://datatracker.ietf.org/doc/html/rfc6396#section-2\n"
"[uint32 timestamp][uint16 message type][uint16 subtype]\n"
"[uint32 length in bytes][record of length bytes]";

struct MRT_RECORD *mrt_read_record(
  int file
) {
  struct MRT_RECORD *record;
  struct MRT_COMMON_HEADER header;
  ssize_t r, bytes;
  uint32_t len;
  struct MRT_TRACEBACK *tr;

  r = mread(file, &header, sizeof(header));
  if (r==0) return NULL; /* EOF */

  record = (struct MRT_RECORD*) malloc (sizeof(struct MRT_RECORD));
  assert(record != NULL);
  memset (record, 0, sizeof(struct MRT_RECORD));

  if (r != sizeof(header)) {
    /* short read at end of file */
    char error[100];

    snprintf(error,99,"MRT header short read %lu of at least %lu bytes",
      r, sizeof(header));
    error[99]=0;
    record->mrt = (struct MRT_COMMON_HEADER*) malloc(r);
    assert(record->mrt!=NULL);
    memcpy ((void*) record->mrt, &header, r); 
    tr = newtraceback(record, error, mrt_overall_format);
    record->trace_read = tr;
    tr->firstbyte = (uint8_t*) tr->mrt;
    tr->afterbyte = tr->firstbyte + r;
    tr->aftermrt = tr->afterbyte;
    record->aftermrt = tr->aftermrt;
    tr->error_firstbyte = tr->firstbyte; 
    tr->error_afterbyte = tr->firstbyte + sizeof(header);
    record->read_failed = TRUE;
    return record; 
  }

  /* got at least an mrt header. Read the number of bytes the header says
   * we should. */
  len = ntohl(header.length);
  bytes = sizeof(header) + (sizeof(uint8_t) * len);
  record->mrt = (struct MRT_COMMON_HEADER*) malloc (bytes);
  if (record->mrt==NULL) {
    /* malloc failure, maybe length is insane */
    char error[100];

    snprintf(error,99,"mrt_read_record out of memory allocating %lu bytes",
        bytes);
    error[99]=0;
    record->mrt = (struct MRT_COMMON_HEADER*) malloc(sizeof(header));
    assert(record->mrt != NULL);
    memcpy ((void*) record->mrt, &header, sizeof(header));
    tr = newtraceback(record, error, mrt_overall_format);
    record->trace_read = tr;
    tr->firstbyte = (uint8_t *) tr->mrt;
    tr->afterbyte = tr->firstbyte + sizeof(header);
    tr->aftermrt = tr->afterbyte;
    record->aftermrt = tr->aftermrt;
    tr->overflow_firstbyte = tr->afterbyte;
    tr->overflow_afterbyte = tr->afterbyte;
    tr->error_firstbyte = (uint8_t*) (&(tr->mrt->length));
    tr->error_afterbyte = tr->error_firstbyte + sizeof(header.length);
    record->read_failed = TRUE;
    return record;
  }

  /* Successful malloc() for buffer to read the MRT record. Read the bytes. */
  memcpy (record->mrt, &header, sizeof(header));
  bytes = sizeof(uint8_t) * len;
  r = mread(file, record->mrt->message, bytes);
  if (r != (sizeof(uint8_t)*len)) {
    /* short read of MRT record */
    char error[100];

    snprintf(error,99,"MRT short read %lu+%lu of %lu+%lu bytes",
      r, sizeof(header), bytes, sizeof(header));
    error[99]=0;
    tr = newtraceback(record, error, mrt_overall_format);
    record->trace_read = tr;
    tr->firstbyte = ((uint8_t *) tr->mrt) + sizeof(header);
    tr->afterbyte = tr->firstbyte + r;
    tr->aftermrt = tr->afterbyte;
    record->aftermrt = tr->aftermrt;
    tr->overflow_firstbyte = tr->afterbyte;
    tr->overflow_afterbyte = tr->firstbyte + bytes;
    tr->error_firstbyte = (uint8_t*) (&(tr->mrt->length));
    tr->error_afterbyte = tr->error_firstbyte + sizeof(header.length);
    tr->tip = mrt_overall_format;
    push_error(record, tr);
    record->read_failed = TRUE;
    return record;
  }
  record->aftermrt = ((uint8_t*) record->mrt) + sizeof(header) + len;

  /* Message is the size it is because of length, so highlight those
   * bytes in the traceback. */
  tr = newtraceback(record, NULL, mrt_overall_format);
  record->trace_read = tr;
  tr->firstbyte = (uint8_t *) &(tr->mrt->length);
  tr->afterbyte = (uint8_t *) tr->mrt->message;

  return record;
}

