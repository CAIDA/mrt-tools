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
#include "msort.h"
#include "truefalse.h"

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
  switch (mrt->mrt->type) {
    case MRT_BGP4MP_ET:
    case MRT_BGP4MP:
      switch (mrt->mrt->subtype) {
        case BGP4MP_MESSAGE:
        case BGP4MP_MESSAGE_AS4:
          if (mrt->bgp4mp) mrt_free_bgp4mp_message(mrt->bgp4mp);
          break;
        default:
          break;
      }
    default:
      break;
  }
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

/* sorting routines */

const char debug_compare_chars[] = "0123456789abcdef";
void debug_compare_bytes (void *a, void *b, size_t bytes, const char *s) {
  int r;
  size_t i;
  uint8_t *aa, *bb;

  r = memcmp(a, b, bytes);
  if (r==0) return;
  printf ("Bytes from %s differ (%d)\n", s, r);
  aa = (uint8_t*) a;
  bb = (uint8_t*) b;
  printf ("  ");
  for (i=0; i<bytes; i++) {
    printf ("%c%c ", debug_compare_chars[aa[i]>>4], 
      debug_compare_chars[aa[i] & 0xf]);
  }
  printf ("\n  ");
  for (i=0; i<bytes; i++) {
    printf ("%c%c ", debug_compare_chars[bb[i]>>4], 
      debug_compare_chars[bb[i] & 0xf]);
  }
  printf ("\n");
  return;
}

static int compare_attributes(void *first, void *second) {
  struct BGP_ATTRIBUTE *a = (struct BGP_ATTRIBUTE*) first;
  struct BGP_ATTRIBUTE *b = (struct BGP_ATTRIBUTE*) second;
  // type is an 8-bit integer
  return (a->type <= b->type);
}

void sort_attributes (struct BGP_ATTRIBUTES *attrs) {
/* Warning: this must be called before decoding the BGP attributes because
 * it will change their location in memory rendering any pointers invalid.
 * This won't work until we change mrt_extract_attributes() so it doesn't
 * decode the attributes while it extracts them.
 */
  struct BGP_ATTRIBUTE **attrpointers, *attr;
  int i;

  attrpointers = (struct BGP_ATTRIBUTE **) malloc (
    sizeof (struct BGP_ATTRIBUTE *) * attrs->numattributes);
  for (i=0; i<attrs->numattributes; i++) 
    attrpointers[i] = attrs->attr + i;
  (void) mergesort((void**) attrpointers, attrs->numattributes,
    compare_attributes);
  attr = (struct BGP_ATTRIBUTE *) malloc (
    sizeof(struct BGP_ATTRIBUTE) * attrs->numattributes);
  for (i=0; i<attrs->numattributes; i++) 
    attr[i] = *(attrpointers[i]);
  memcpy (attrs->attr, attr, 
    sizeof(struct BGP_ATTRIBUTE) * attrs->numattributes);
  free(attr);
  free(attrpointers);
  return;
}

static int compare_communities(void *first, void *second) {
  // from struct BGP_COMMUNITIES where they are in host byte order
  uint32_t *a = (uint32_t *) first;
  uint32_t *b = (uint32_t *) second;
  return (*a <= *b);
}

void sort_communities(struct BGP_COMMUNITIES *com) {
  uint32_t **cm_pointers, *cm;
  int i;
  
  cm_pointers = (uint32_t **) malloc ( sizeof (uint32_t*) * com->num);
  for (i=0; i<com->num; i++) cm_pointers[i] = com->c + i;
  (void) mergesort((void**) cm_pointers, com->num, compare_communities);
  cm = (uint32_t *) malloc ( sizeof(uint32_t) * com->num);
  for (i=0; i<com->num; i++) cm[i] = *(cm_pointers[i]);
  debug_compare_bytes (com->c, cm, sizeof(uint32_t) * com->num,
    "DEBUG communities");
  memcpy (com->c, cm, sizeof(uint32_t) * com->num);
  free(cm);
  free(cm_pointers);
  return;
}

static int compare_large_communities(void *first, void *second) {
  struct BGP_LARGE_COMMUNITY *a = (struct BGP_LARGE_COMMUNITY*) first;
  struct BGP_LARGE_COMMUNITY *b = (struct BGP_LARGE_COMMUNITY*) second;
  // struct BGP_LARGE_COMMUNITY uses host byte order
  if (a->global != b->global) return (a->global < b->global);
  if (a->local1 != b->local1) return (a->local1 < b->local1);
  return (a->local2 <= b->local2);
}

void sort_large_communities (struct BGP_LARGE_COMMUNITIES *com) {
  struct BGP_LARGE_COMMUNITY **cm_pointers, *cm;
  int i;

  cm_pointers = (struct BGP_LARGE_COMMUNITY **) malloc (
    sizeof (struct BGP_LARGE_COMMUNITY *) * com->num);
  for (i=0; i<com->num; i++) cm_pointers[i] = (com->c) + i;
  (void) mergesort((void**) cm_pointers, com->num,
           compare_large_communities);
  cm = (struct BGP_LARGE_COMMUNITY *) malloc (
    sizeof(struct BGP_LARGE_COMMUNITY) * com->num);
  for (i=0; i<com->num; i++) 
    cm[i] = *(cm_pointers[i]);
  debug_compare_bytes (com->c, cm,
    sizeof(struct BGP_LARGE_COMMUNITY) * com->num, "DEBUG large communities");
  memcpy (com->c, cm, sizeof(struct BGP_LARGE_COMMUNITY) * com->num);
  free(cm);
  free(cm_pointers);
  return;
}

uint64_t ntoh64 (uint64_t input) {
// Network to host byte order for 64-bit integers
  uint32_t *two_words = (uint32_t*) (&input);
  uint32_t work[2];
  uint64_t *output = (uint64_t*) (&work);

# if __BYTE_ORDER == __LITTLE_ENDIAN
  work[0]=ntohl(two_words[1]);
  work[1]=ntohl(two_words[0]);
  return *output;
# else // __BIG_ENDIAN
  return input
# endif // __BIG_ENDIAN
}

static int compare_extended_communities(void *first, void *second) {
  struct BGP_EXTENDED_COMMUNITY *a = (struct BGP_EXTENDED_COMMUNITY*) first;
  struct BGP_EXTENDED_COMMUNITY *b = (struct BGP_EXTENDED_COMMUNITY*) second;

  if (a->type.bits.type != b->type.bits.type) 
    return (a->type.bits.type <= b->type.bits.type);
  switch (a->type.bits.type) {
    case 0: /* two-octet global AS:local */
      if (a->as.global != b->as.global) return (a->as.global < b->as.global);
      return (a->as.local <= b->as.local);
    case 1: /* two-octet IP:local */
      if (a->ip.global.whole != b->ip.global.whole)
        return (ntohl(a->ip.global.whole) < ntohl(b->ip.global.whole));
      return (a->ip.local <= b->ip.local);
    case 2: /* opaque w/ sub-type */
      return (a->opaque.value <= b->opaque.value);
    default: /* opaque */
      return (a->one.value <= b->one.value);
  }
}

void sort_extended_communities (struct BGP_EXTENDED_COMMUNITIES *com) {
  struct BGP_EXTENDED_COMMUNITY **cm_pointers, *cm;
  int i;

  cm_pointers = (struct BGP_EXTENDED_COMMUNITY **) malloc (
    sizeof (struct BGP_EXTENDED_COMMUNITY *) * com->num);
  for (i=0; i<com->num; i++) cm_pointers[i] = (com->c) + i;
  (void) mergesort((void**) cm_pointers, com->num,
           compare_extended_communities);
  cm = (struct BGP_EXTENDED_COMMUNITY *) malloc (
    sizeof(struct BGP_EXTENDED_COMMUNITY) * com->num);
  for (i=0; i<com->num; i++) 
    cm[i] = *(cm_pointers[i]);
  memcpy (com->c, cm, sizeof(struct BGP_EXTENDED_COMMUNITY) * com->num);
  free(cm);
  free(cm_pointers);
  return;
}

static int compare_nlri(void *first, void *second) {
  struct NLRI *a = (struct NLRI*) first;
  struct NLRI *b = (struct NLRI*) second;
  uint64_t aa, bb;

  if (a->address_family != b->address_family)
    return (a->address_family < b->address_family);
  switch (a->address_family) {
    case BGP4MP_AFI_IPV4:
      if (a->ipv4.whole == b->ipv4.whole) 
        // Least specific prefix first. See note below.
        return (a->prefix_len <= b->prefix_len);
      return (ntohl(a->ipv4.whole) <= ntohl(b->ipv4.whole));
    case BGP4MP_AFI_IPV6:
      if ((a->ipv6.network == b->ipv6.network) &&
          (a->ipv6.host == b->ipv6.host)) {
        // Least specific prefix first. See note below.
        return (a->prefix_len <= b->prefix_len);
      }
      if (a->ipv6.network != b->ipv6.network) {
        aa=ntoh64(a->ipv6.network);
        bb=ntoh64(b->ipv6.network);
        return (aa < bb);
      }
      aa=ntoh64(a->ipv6.host);
      bb=ntoh64(b->ipv6.host);
      return (aa <= bb);
    default:
      return TRUE; // this is an error, so don't change the sort order
  }
  /* Not sure the most-specific prefix logic here is reasonable.
   * Not really possible to sort most specific routes within a covering
   * route first using an array structure. Would need a tree for that.
   * Least specific prefix is sensible from a human perspective but the
   * opposite of what's needed by a router. If I put the most specific
   * prefixes first regardless of the address, it'll make sense to a router
   * but not a human.
   */
}

void sort_nlri (struct NLRI_LIST *nlris) {
  struct NLRI **nlri_pointers, *prefixes;
  int i;

  nlri_pointers = (struct NLRI **) malloc (
    sizeof (struct NLRI *) * nlris->num_nlri);
  for (i=0; i<nlris->num_nlri; i++) nlri_pointers[i] = (nlris->prefixes) + i;
  (void) mergesort((void**) nlri_pointers, nlris->num_nlri,
           compare_nlri);
  prefixes = (struct NLRI *) malloc (sizeof(struct NLRI) * nlris->num_nlri);
  for (i=0; i<nlris->num_nlri; i++) 
    prefixes[i] = *(nlri_pointers[i]);
  memcpy (nlris->prefixes, prefixes, sizeof(struct NLRI) * nlris->num_nlri);
  free(prefixes);
  free(nlri_pointers);
  return;
}


/* end sorting routines */

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

static const char *mrt_mp_unreach_information =
"https://datatracker.ietf.org/doc/html/rfc4760#section-4\n"
"[uint16 address family][uint8 SAFI (unicast/multicast)]\n"
"[nlri information until the end of the buffer]\n"
"NLRI: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Network Layer Reachability Information\n"
"[uint8 prefix length][0 or more bytes, minimum needed for the prefix len]\n"
"e.g. /0 needs 0 bytes, /60 needs 8, /128 needs 16.";

void mrt_attribute_mp_unreach_nlri (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  struct BGP_MP_UNREACH_HEADER *h;
  size_t minsize;
  uint8_t badflag = FALSE;
  struct BGP_MP_UNREACH *unreach;

  if (attributes->mp_unreach_nlri) {
    snprintf(error, 99, "duplicate MP_UNREACH_NLRI attribute");
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
  minsize = sizeof(struct BGP_MP_UNREACH_HEADER);
  h = (struct BGP_MP_UNREACH_HEADER*) attribute->content;
  if ((attribute->after - attribute->content) < minsize) badflag=TRUE;
  if (badflag) {
    snprintf(error, 99,
        "short MP_UNREACH_NRLI attribute %u bytes of minimum %u",
        (unsigned int) (attribute->after - attribute->content),
        (unsigned int) minsize);
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_mp_unreach_information);
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
    case BGP4MP_AFI_IPV6:
      break;
    default:
      snprintf(error, 99, "MP_UNREACH_NLRI address family %x unknown",
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
  /* malloc a buffer for BGP_MP_REACH and populate the reach->l structure
   * with the decoded and traced NRLI information */
  unreach = (struct BGP_MP_UNREACH*) mrt_nlri_deserialize (record,
    attribute->content + minsize, attribute->after,
    &(attribute->header->length16), h->address_family, TRUE,
    ((uint8_t*) &(unreach->l)) - ((uint8_t*) unreach));
    /* note that "&(unreach->l) - unreach)" is just math calculating the
     * offset of unreach->l within an unreach structure. It is not a pointer,
     * so does not depend on unreach already having a value */
  if (unreach->l.faults) {
    snprintf(error, 99, "MP_UNREACH_NRLI decode fault: %s",
        (unreach->l.error)?unreach->l.error->error:"");
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_mp_unreach_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->after;
    attribute->trace->error_firstbyte = attribute->content + minsize;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
  }
  unreach->header = h;
  unreach->attribute = attribute;
  unreach->address_family = h->address_family;
  unreach->safi = h->subsequent_address_family;
  attribute->mp_unreach_nlri = unreach;
  attributes->mp_unreach_nlri = unreach;
  return ;
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
  struct ipv4_address *ip4;
  struct ipv6_address *ip6;

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
    /* this is the actual minsized used later if badflag=false
     * size before next hop, plus variable size next hop plus reserved octet
     */
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
    /* note that "&(reach->l) - reach)" is just math calculating the offset
     * of reach->l within a reach structure. It is not a pointer, so does
     * not depend on reach already having a value */
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
      ip4 = (struct ipv4_address*) (h->next_hop);
      reach->next_hop = *ip4;
      break;
    case BGP4MP_AFI_IPV6:
      ip6 = (struct ipv6_address*) (h->next_hop);
      reach->global_next_hop = *ip6;
      if (h->next_hop_len == 32) {
        ip6 = (struct ipv6_address*) (h->next_hop + 16);
        reach->local_next_hop = *ip6;
      }
      break;
    default: /* unreachable */
      break;
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

  if (attributes->aggregator_as && (attributes->aggregator_as > 65565)) {
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

  attributes->as2or4 = BGP_AS_PATH_IS_AS2;
  attributes->attribute_aggregator = attribute;
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
  uint32_t aggregator_as;

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

  if (length == 6) aggregator_as =
    (uint32_t) ntohs(*((uint16_t*) attribute->content));
  else aggregator_as = ntohl(*((uint32_t*) attribute->content));

  /* if it's a 4-byte aggregator_as and we already have an aggregator AS then
   * this is an invalid duplicate */
  if (attributes->aggregator_as && (length != 6)) {
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
  /* if it's a 2-byte aggregator AS and we already have a 2-byte aggregator
   * AS and it's not the same as this one then something is wrong. */
  if (attributes->aggregator_as && (attributes->aggregator_as < 65536) &&
      (attributes->aggregator_as != aggregator_as)) {
    snprintf(error, 99, "mismatch between AGGREGATOR (%u) and AGGREGATOR4 (%u)"
      " AS numbers", aggregator_as, attributes->aggregator_as);
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
  /* Note: not detecting errors where we don't use the proper 2-byte AS
   * to mean an AGGREGATOR4 attribute is present */
  /* If it's a 2-byte aggregator AS and we already have an aggregator AS
   * from an AGGREGATOR4 attribute, keep it */
  if (attributes->aggregator_as) {
    return;
  }

  /* Otherwise, use this aggregator attribute */
  if (length==8) attributes->as2or4 = BGP_AS_PATH_IS_AS4;
  attributes->attribute_aggregator = attribute;
  attributes->aggregator_as = aggregator_as;
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

  attributes->attribute_next_hop = attribute;
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

  attributes->attribute_origin = attribute;
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

static const char *mrt_med_attribute_information =
"https://datatracker.ietf.org/doc/html/rfc4271#section-4.3\n"
"Path Attributes section, part (d) MULTI_EXIT_DISC\n"
"[uint32 med]";

void mrt_attribute_med (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  uint32_t *p;

  if (attribute->after - attribute->content != 4) {
    snprintf(error, 99,
        "invalid BGP MED attribute length expecting 4 bytes got %u",
        (unsigned int) (attribute->after - attribute->content));
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_med_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  if (attributes->med_set) {
    snprintf(error, 99, "duplicate BGP MED attribute");
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_med_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }

  attributes->attribute_med = attribute;
  attributes->med_set = TRUE;
  p = (uint32_t*) attribute->content;
  attributes->med = ntohl(*p);
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

void mrt_attribute_as_path(
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];

  if (attributes->attribute_as_path) {
    snprintf(error, 99, "duplicate AS_PATH attribute");
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
  attributes->attribute_as_path = attribute;
  /* deferred decoding because we might have to deal with both
   * AS_PATH and AS4_PATH */
  return;
}

void mrt_attribute_as4_path(
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];

  if (attributes->attribute_as4_path) {
    snprintf(error, 99, "duplicate AS4_PATH attribute");
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
  attributes->as2or4 = BGP_AS_PATH_IS_AS2;
  attributes->attribute_as4_path = attribute;
  /* deferred decoding because we might have to deal with both
   * AS_PATH and AS4_PATH */
  return;
}

uint32_t mrt_check_as_path_bytes(
  struct BGP_ATTRIBUTE *attribute
, size_t as_bytes
) {
/* Check if the attribute contains an AS_PATH using AS numbers of length
 * as_bytes.
 * If it decodes to exactly the number of bytes in the buffer then yes.
 * Otherwise no.
 */
  uint8_t *p = attribute->content;
  struct BGP_AS_PATH_SEGMENT *segment;
  size_t bytes;
  uint32_t segments = 0;

  while (attribute->after - p >= 2) {
    segment = (struct BGP_AS_PATH_SEGMENT*) p;
    if ((segment->type != BGP_AS_SET) && (segment->type != BGP_AS_SEQUENCE))
      return 0;
    bytes = as_bytes * ((size_t) segment->ascount);
    p += sizeof(struct BGP_AS_PATH_SEGMENT) + bytes;
    segments ++;
  }
  if (p > attribute->after) return 0;

  return segments;
}

uint32_t mrt_check_as_path_2bytes(
  struct BGP_ATTRIBUTE *attribute
) {
/* Check if the attribute contains an AS_PATH using AS numbers of length 2.
 * If it decodes to exactly the number of bytes in the buffer and
 * none of the ASes are zero then yes. Otherwise no.
 */
  uint8_t *p = attribute->content;
  struct BGP_AS_PATH_SEGMENT *segment;
  size_t bytes;
  uint32_t segments = 0, i;
  uint16_t *as;

  while (attribute->after - p >= 2) {
    segment = (struct BGP_AS_PATH_SEGMENT*) p;
    if ((segment->type != BGP_AS_SET) && (segment->type != BGP_AS_SEQUENCE))
      return 0;
    /* make sure none of the 2-byte ASes are zero. */
    as = (uint16_t*) (p + sizeof(struct BGP_AS_PATH_SEGMENT));
    for (i=0; i<= (uint32_t) segment->ascount; i++) {
      if (as[i] == 0) return 0;
    }
    bytes = ((size_t) segment->ascount) * 2;
    p += sizeof(struct BGP_AS_PATH_SEGMENT) + bytes;
    segments ++;
  }
  if (p > attribute->after) return 0;

  return segments;
}

void mrt_attribute_decodepath4 (
  struct BGP_ATTRIBUTES *attributes
, uint32_t segments
/* Note that the AS_PATH has already been determined to contain 4-byte AS
 * numbers and decodes to the exact buffer size, so error checking is
 * not necessary here.
 */
) {
  struct BGP_AS_PATH *path;
  struct BGP_AS_PATH_SEGMENT *from, *to;
  uint8_t *p;
  uint32_t seg, i, ascount;
  size_t allocsize;

  allocsize = sizeof(struct BGP_AS_PATH) +
    (sizeof(struct BGP_AS_PATH_SEGMENT*) * segments);
  path = malloc(allocsize);
  memset (path, 0, allocsize);
  path->numsegments = segments;

  p = attributes->attribute_as_path->content;
  for (seg=0; seg<segments; seg++) {
    from = (struct BGP_AS_PATH_SEGMENT*) p;
    to = malloc (sizeof(struct BGP_AS_PATH_SEGMENT) +
      (sizeof(uint32_t) * from->ascount));
    to->type = from->type;
    to->ascount = from->ascount;
    ascount = (uint32_t) (to->ascount);
    for (i=0; i<ascount; i++) {
      to->as4_list[i] = ntohl(from->as4_list[i]);
    }
    path->path[seg] = to;
    p += (sizeof(struct BGP_AS_PATH_SEGMENT) + (sizeof(uint32_t) * ascount));
  }
  attributes->path = path;
  return;
}

struct BGP_AS_PATH_SEGMENT2 {
  uint8_t type;
  uint8_t ascount;
  uint16_t as2_list[];
} __attribute__ ((__packed__));

void mrt_attribute_decodepath2 (
  struct BGP_ATTRIBUTES *attributes
, uint32_t segments
/* Note that the AS_PATH has already been determined to contain 2-byte AS
 * numbers and decodes to the exact buffer size, so error checking is
 * not necessary here.
 */
) {
  struct BGP_AS_PATH *path;
  struct BGP_AS_PATH_SEGMENT2 *from;
  struct BGP_AS_PATH_SEGMENT *to;
  uint8_t *p;
  uint32_t seg, i, ascount;
  size_t allocsize;

  allocsize = sizeof(struct BGP_AS_PATH) +
    (sizeof(struct BGP_AS_PATH_SEGMENT*) * segments);
  path = malloc(allocsize);
  memset (path, 0, allocsize);
  path->numsegments = segments;

  p = attributes->attribute_as_path->content;
  for (seg=0; seg<segments; seg++) {
    from = (struct BGP_AS_PATH_SEGMENT2*) p;
    to = malloc (sizeof(struct BGP_AS_PATH_SEGMENT) +
      (sizeof(uint32_t) * from->ascount));
    to->type = from->type;
    to->ascount = from->ascount;
    ascount = (uint32_t) (to->ascount);
    for (i=0; i<ascount; i++) {
      to->as4_list[i] = (uint32_t) ntohs(from->as2_list[i]);
    }
    path->path[seg] = to;
    p += (sizeof(struct BGP_AS_PATH_SEGMENT2) + (sizeof(uint16_t) * ascount));
  }
  attributes->path = path;
  return;
}

void mrt_attribute_decodepath (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, uint8_t *firstbyte
, uint8_t *afterbyte
) {
  char error[100];
  struct BGP_AS_PATH *path;
  uint32_t twobytes, fourbytes;
 
  if (!attributes->attribute_as_path && attributes->attribute_as4_path) {
    snprintf(error, 99, "Missing required AS_PATH");
    error[99]=0;
    path = malloc(sizeof(struct BGP_AS_PATH));
    memset (path, 0, sizeof(struct BGP_AS_PATH));
    path->fault = 1;
    path->trace =
      newtraceback(record, error, mrt_path_attribute_information);
    path->trace->firstbyte = firstbyte;
    path->trace->afterbyte = afterbyte;
    path->trace->error_firstbyte = firstbyte;
    path->trace->error_afterbyte = afterbyte;
    path->fault = TRUE;
    attributes->path = path;
    return;
  }
  if (!attributes->attribute_as_path) {
    /* likely a withdrawal message */
    return;
  }
  twobytes = mrt_check_as_path_2bytes(attributes->attribute_as_path);
  if (attributes->attribute_as4_path) {
    /* decode and merge AS_PATH and AS4_PATH */
    fourbytes = mrt_check_as_path_bytes(attributes->attribute_as4_path, 4);
    if (!twobytes) {
      snprintf(error, 99, "AS_PATH failed to parse");
      error[99]=0;
      path = malloc(sizeof(struct BGP_AS_PATH));
      memset (path, 0, sizeof(struct BGP_AS_PATH));
      path->trace =
        newtraceback(record, error, mrt_path_attribute_information);
      path->trace->firstbyte = attributes->attribute_as_path->trace->firstbyte;
      path->trace->afterbyte = attributes->attribute_as_path->trace->afterbyte;
      path->trace->error_firstbyte = path->trace->firstbyte;
      path->trace->error_afterbyte = path->trace->afterbyte;
      path->fault = TRUE;
      attributes->path = path;
      return;
    }  
    if (!fourbytes) {
      snprintf(error, 99, "AS4_PATH failed to parse");
      error[99]=0;
      path = malloc(sizeof(struct BGP_AS_PATH));
      memset (path, 0, sizeof(struct BGP_AS_PATH));
      path->trace =
        newtraceback(record, error, mrt_path_attribute_information);
      path->trace->firstbyte = 
        attributes->attribute_as4_path->trace->firstbyte;
      path->trace->afterbyte = 
        attributes->attribute_as4_path->trace->afterbyte;
      path->trace->error_firstbyte = path->trace->firstbyte;
      path->trace->error_afterbyte = path->trace->afterbyte;
      path->fault = TRUE;
      attributes->path = path;
      return;
    }
    if (twobytes < fourbytes) {
      snprintf(error, 99, "AS_PATH is inexplicably shorter than AS4_PATH."
        "Impossible to merge.");
      error[99]=0;
      path = malloc(sizeof(struct BGP_AS_PATH));
      memset (path, 0, sizeof(struct BGP_AS_PATH));
      path->trace =
        newtraceback(record, error, mrt_path_attribute_information);
      path->trace->firstbyte = 
        attributes->attribute_as4_path->trace->firstbyte;
      path->trace->afterbyte = 
        attributes->attribute_as4_path->trace->afterbyte;
      path->trace->error_firstbyte = path->trace->firstbyte;
      path->trace->error_afterbyte = path->trace->afterbyte;
      path->fault = TRUE;
      attributes->path = path;
      return;
    }
    /* AS4_PATH contains the 4-byte AS path up to the last router that could
     * handle 4-byte AS paths. AS_PATH contains 0 or more two-byte AS numbers
     * from later in the path. Initialize our path with AS_PATH and then
     * copy in the contents of AS4_PATH. */
    mrt_attribute_decodepath2(attributes, twobytes);
    /* FIXME: actually merge the contents of AS4_PATH */

    return;
  }
  /* only have AS_PATH which may use either 2 or 4 byte AS numbers */
  fourbytes = mrt_check_as_path_bytes(attributes->attribute_as_path, 4);
  if (!twobytes && !fourbytes) {
    snprintf(error, 99, "AS_PATH failed to parse");
    error[99]=0;
    path = malloc(sizeof(struct BGP_AS_PATH));
    memset (path, 0, sizeof(struct BGP_AS_PATH));
    path->trace =
      newtraceback(record, error, mrt_path_attribute_information);
    path->trace->firstbyte = attributes->attribute_as_path->trace->firstbyte;
    path->trace->afterbyte = attributes->attribute_as_path->trace->afterbyte;
    path->trace->error_firstbyte = path->trace->firstbyte;
    path->trace->error_afterbyte = path->trace->afterbyte;
    path->fault = TRUE;
    attributes->path = path;
    return;
  }
  if (twobytes && fourbytes) {
    if (attributes->as2or4 == BGP_AS_PATH_IS_AS2) fourbytes = 0;
    else if (attributes->as2or4 == BGP_AS_PATH_IS_AS4) twobytes = 0;
    /* else set error later that we couldn't reliably decode the AS path */
  }

  if (fourbytes) mrt_attribute_decodepath4(attributes, fourbytes);
  else mrt_attribute_decodepath2(attributes, twobytes);
  attributes->path->attr = attributes->attribute_as_path;
  attributes->path->trace = attributes->attribute_as_path->trace;
  if (twobytes && fourbytes) {
    snprintf(error, 99,
      "Ambiguous whether AS_PATH uses 2 or 4 byte AS numbers. Decoded as 4.");
    error[99]=0;
    attributes->path->trace =
      newtraceback(record, error, mrt_path_attribute_information);
    attributes->path->trace->firstbyte = 
      attributes->attribute_as_path->trace->firstbyte;
    attributes->path->trace->afterbyte = 
      attributes->attribute_as_path->trace->afterbyte;
    attributes->path->trace->warning = TRUE;
  }
  return;
}

char *mrt_aspath_to_string (struct BGP_AS_PATH *path) {
  char *s, *p;
  size_t length = 1;
  uint32_t segment, i;

  for (segment=0; segment < path->numsegments; segment++) {
    length += 6 + (11 * ((uint32_t) path->path[segment]->ascount));
  }
  s = (char*) malloc(length);
  s[0]=0;
  p = s;
  for (segment=0; segment<path->numsegments; segment++) {
    if (path->path[segment]->type == BGP_AS_SET) {
      strcpy(p, "[ ");
      p += 2;
    }
    for (i=0; i<path->path[segment]->ascount; i++) {
      sprintf (p, "%u ", path->path[segment]->as4_list[i]);
      p += strlen(p);
    }
    if (path->path[segment]->type == BGP_AS_SET) {
      strcpy(p, "] ");
      p += 2;
    }
  }
  if ((p>s) && (p[-1]==' ')) p[-1] = 0;
  return s;
}

static const char *mrt_communities_attribute_information =
"https://datatracker.ietf.org/doc/html/rfc1997\n"
"[uint8 flags][uint8 type 08][uint8 or uint16 length (extended length flag)]\n"
"[uint32_t community][uint32_t community][...][uint32_t community]\n"
"";

void mrt_attribute_communities (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  uint32_t num, i, *p;
  struct BGP_COMMUNITIES *c;
  size_t csize;

  if (attributes->communities) {
    snprintf(error, 99,
      "duplicate communities attribute ignored");
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num = (attribute->after - attribute->content);
  if ((num % sizeof(uint32_t)) != 0) {
    snprintf(error, 99, "communities are 32 bits each, but %u content "
      "size is not divisible by 4", num);
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num /= 4;
  csize = sizeof(struct BGP_COMMUNITIES) + (sizeof(uint32_t) * num);

  c = (struct BGP_COMMUNITIES*) malloc (csize);
  memset (c, 0, csize);
  c->num = num;
  c->attr = attribute;
  p = (uint32_t*) attribute->content;
  for (i=0; i<num; i++, p++) {
    c->c[i] = ntohl(*p);
  }
  attributes->communities = c;

  return;
}

char *mrt_communities_to_string (struct BGP_COMMUNITIES *communities) {
  char *s, *p;
  size_t length;
  uint32_t i;

  if (!communities) return NULL;
  length = 2 + (12 * communities->num);
  s = (char*) malloc(length);
  s[0]=0;
  p = s;
  for (i=0; i < communities->num; i++) {
    sprintf (p, "%u:%u ", (communities->c[i] & 0xFFFF0000) >> 16,
      (communities->c[i] & 0xFFFF));
    p += strlen(p);
  }
  if ((p>s) && (p[-1]==' ')) p[-1] = 0;
  return s;
}

static const char *mrt_large_communities_attribute_information =
"https://datatracker.ietf.org/doc/html/rfc8092\n"
"[uint8 flags][uint8 type 32][uint8 or uint16 length (extended length flag)]\n"
"[community][community][...][community]\n"
"Where community = [uint32 global][uint32 local1][uint32 local2]\n"
"";

void mrt_attribute_large_communities (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  uint32_t num, i;
  struct BGP_LARGE_COMMUNITY *p;
  struct BGP_LARGE_COMMUNITIES *c;
  size_t csize;

  if (attributes->large_communities) {
    snprintf(error, 99,
      "duplicate large communities attribute ignored");
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_large_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num = (attribute->after - attribute->content);
  if ((num % sizeof(struct BGP_LARGE_COMMUNITY)) != 0) {
    snprintf(error, 99, "large communities are 12 bytes each, but %u content "
      "size is not divisible by 12", num);
    error[99]=0;
    attribute->trace =
      newtraceback(record, error, mrt_large_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num /= sizeof(struct BGP_LARGE_COMMUNITY);
  csize = sizeof(struct BGP_LARGE_COMMUNITIES) + 
    (sizeof(struct BGP_LARGE_COMMUNITY) * num);

  c = (struct BGP_LARGE_COMMUNITIES*) malloc (csize);
  memset (c, 0, csize);
  c->num = num;
  c->attr = attribute;
  p = (struct BGP_LARGE_COMMUNITY*) attribute->content;
  for (i=0; i<num; i++, p++) {
    c->c[i].global = ntohl(p->global);
    c->c[i].local1 = ntohl(p->local1);
    c->c[i].local2 = ntohl(p->local2);
  }
  attributes->large_communities = c;

  return;
}

char *mrt_large_communities_to_string (
  struct BGP_LARGE_COMMUNITIES *communities
) {
  char *s, *p;
  size_t length;
  uint32_t i;

  if (!communities) return NULL;
  length = 2 + (38 * communities->num);
  s = (char*) malloc(length);
  s[0]=0;
  p = s;
  for (i=0; i < communities->num; i++) {
    sprintf (p, "%u:%u:%u ", communities->c[i].global, 
      communities->c[i].local1, communities->c[i].local2);
    p += strlen(p);
  }
  if ((p>s) && (p[-1]==' ')) p[-1] = 0;
  return s;
}

static const char *mrt_extended_communities_attribute_information =
"https://datatracker.ietf.org/doc/html/rfc4360#section-1\n"
"[community][community][...][community]\n"
"Where community = [uint8 type][7 bytes - variable]\n"
"";

void mrt_attribute_extended_communities (
  struct MRT_RECORD *record
, struct BGP_ATTRIBUTES *attributes
, struct BGP_ATTRIBUTE *attribute
) {
  char error[100];
  uint32_t num, i;
  struct BGP_EXTENDED_COMMUNITY *p;
  struct BGP_EXTENDED_COMMUNITIES *c;
  size_t csize;
  uint8_t t;

  if (attributes->extended_communities) {
    snprintf(error, 99,
      "duplicate extended communities attribute ignored");
    error[99]=0;
    attribute->trace = newtraceback(record, error,
      mrt_extended_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num = (attribute->after - attribute->content);
  if ((num % sizeof(struct BGP_EXTENDED_COMMUNITY)) != 0) {
    snprintf(error, 99, "large communities are %u bytes each, "
      "but %u content size is not divisible by %u", 
      (unsigned int) sizeof(struct BGP_EXTENDED_COMMUNITY), num,
      (unsigned int) sizeof(struct BGP_EXTENDED_COMMUNITY));
    error[99]=0;
    attribute->trace = newtraceback(record, error,
      mrt_extended_communities_attribute_information);
    attribute->trace->firstbyte = (uint8_t*) attribute->header;
    attribute->trace->afterbyte = attribute->trace->firstbyte + 1;
    attribute->trace->error_firstbyte = attribute->trace->firstbyte;
    attribute->trace->error_afterbyte = attribute->after;
    attribute->fault = TRUE;
    return ;
  }
  num /= sizeof(struct BGP_EXTENDED_COMMUNITY);
  csize = sizeof(struct BGP_EXTENDED_COMMUNITIES) + 
    (sizeof(struct BGP_EXTENDED_COMMUNITY) * num);

  c = (struct BGP_EXTENDED_COMMUNITIES*) malloc (csize);
  memset (c, 0, csize);
  c->num = num;
  c->attr = attribute;
  p = (struct BGP_EXTENDED_COMMUNITY*) attribute->content;
  for (i=0; i<num; i++, p++) {
#   if __BYTE_ORDER == __LITTLE_ENDIAN
      switch (p->type.bits.type) {
        case 0: /* two-octet global AS:local */
          c->c[i].as.high = p->as.high;
          c->c[i].as.subtype = p->as.subtype;
          c->c[i].as.global = ntohs(p->as.global);
          c->c[i].as.local = ntohl(p->as.local);
          break;
        case 1: /* two-octet IP:local */
          c->c[i].ip.high = p->ip.high;
          c->c[i].ip.subtype = p->ip.subtype;
          c->c[i].ip.global = p->ip.global;
          c->c[i].ip.local = ntohs(p->ip.local);
          break;
        case 2: /* opaque w/ sub-type */
          c->c[i] = *p;
          t = p->opaque.value_bytes[0];
          p->opaque.value_bytes[0] = p->opaque.value_bytes[5];
          p->opaque.value_bytes[5] = t;
          t = p->opaque.value_bytes[1];
          p->opaque.value_bytes[1] = p->opaque.value_bytes[4];
          p->opaque.value_bytes[4] = t;
          t = p->opaque.value_bytes[2];
          p->opaque.value_bytes[2] = p->opaque.value_bytes[3];
          p->opaque.value_bytes[3] = t;
          break;
        default: /* opaque */
          c->c[i] = *p;
          t = p->one.value_bytes[0];
          p->one.value_bytes[0] = p->one.value_bytes[6];
          p->one.value_bytes[6] = t;
          t = p->one.value_bytes[1];
          p->one.value_bytes[1] = p->one.value_bytes[5];
          p->one.value_bytes[5] = t;
          t = p->one.value_bytes[2];
          p->one.value_bytes[2] = p->one.value_bytes[4];
          p->one.value_bytes[4] = t;
          break;
      } // switch (p->type.bits.type)
#   else // __BIG_ENDIAN
      c->c[i] = *p;
#   endif // __BIG_ENDIAN
  }
  attributes->extended_communities = c;

  return;
}

char *mrt_extended_communities_to_string (
  struct BGP_EXTENDED_COMMUNITIES *communities
) {
  char *s, *p;
  size_t length;
  uint32_t i;

  if (!communities) return NULL;
  length = 2 + (40 * communities->num);
  s = (char*) malloc(length);
  s[0]=0;
  p = s;
  for (i=0; i < communities->num; i++) {
    switch (communities->c[i].type.bits.type) {
      case 0: /* two-octet global AS:local */
        sprintf(p, "%02xsub%02x,%u:%u ", 
          (uint32_t) communities->c[i].type.type,
          (uint32_t) communities->c[i].as.subtype, 
          (uint32_t) communities->c[i].as.global,
          communities->c[i].as.local);
        break;
      case 1: /* two-octet IP:local */
        sprintf(p, "%02xsub%02x," PRI_IPV4 ":%u ",
          (uint32_t) communities->c[i].type.type,
          (uint32_t)  communities->c[i].ip.subtype, 
          PRI_IPV4_V(communities->c[i].ip.global),
          (uint32_t) communities->c[i].ip.local);
        break;
      case 2: /* opaque w/ sub-type */
        sprintf(p, "%02xsub%02x,%012lx ",
          (uint32_t) communities->c[i].type.type,
          (uint32_t)  communities->c[i].opaque.low, 
          (uint64_t)  communities->c[i].opaque.value);
        break;
      default: /* opaque without subtype */
        sprintf(p, "%02x,%014lx ", communities->c[i].type.type,
          (uint64_t) communities->c[i].one.value);
        break;
    }
    p += strlen(p);
  }
  if ((p>s) && (p[-1]==' ')) p[-1] = 0;
  return s;
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
        mrt_attribute_as_path(record, attributes, attribute);
        break;
      case BGP_AS4_PATH:
        mrt_attribute_as4_path(record, attributes, attribute);
        break;
      case BGP_NEXT_HOP:
        mrt_attribute_next_hop(record, attributes, attribute);
        break;
      case BGP_MED:
        mrt_attribute_med(record, attributes, attribute);
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
      case BGP_MP_UNREACH_NLRI:
        mrt_attribute_mp_unreach_nlri(record, attributes, attribute);
        break;
      case BGP_COMMUNITIES:
        mrt_attribute_communities(record, attributes, attribute);
        break;
      case BGP_LARGE_COMMUNITIES:
        mrt_attribute_large_communities(record, attributes, attribute);
        break;
      case BGP_EXTENDED_COMMUNITIES:
        mrt_attribute_extended_communities(record, attributes, attribute);
        break;
      default:
        break;
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
    mrt_attribute_decodepath (record, attributes, firstbyte, afterbyte);
  }

  /* sort here */

  return attributes;
}

void mrt_free_path (
  struct BGP_AS_PATH *path
) {
  int i;

  if (!path) return;
  if (path->trace) {
    if (!(path->attr && (path->attr->trace == path->trace)))
      free(path->trace);
  }
  for (i=0; i<path->numsegments; i++)
    if (path->path[i]) free(path->path[i]);
  free(path);
  return;
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
      "NLRI prefix length %u requires %u bytes but only has %u",
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
    case BGP4MP_AFI_IPV6:
      if (nlri->prefix_len <= 128) break;
    case BGP4MP_AFI_IPV4:
      if (nlri->prefix_len <= 32) break;
      /* insane netmask */
      nlri->fault_flag = TRUE;
      snprintf (error, 199,
        "NLRI prefix length %u too long for address family %s",
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
        "NLRI unknown address family 0x%x with prefix of length %u",
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
          "NLRI IPv4 prefix " PRI_IPV4 "/%u is wrong. Would be " 
          PRI_IPV4 "/%u",
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
          "NLRI IPv6 prefix " PRI_IPV6 "/%u is wrong. Would be " 
          PRI_IPV6 "/%u",
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
      break;
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
        "NLRI buffer of %u bytes did not align with the encoded prefixes",
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

void mrt_free_attributes(struct BGP_ATTRIBUTES *attributes)
{
  int i;
  if (!attributes) return;

  mrt_free_path (attributes->path);
  if (attributes->communities) free(attributes->communities);
  if (attributes->large_communities) free(attributes->large_communities);
  if (attributes->extended_communities) free(attributes->extended_communities);
  for (i=0; i < attributes->numattributes; i++) {
    if (attributes->attr[i].trace)
      free(attributes->attr[i].trace);
    switch (attributes->attr[i].type) {
      /* type-specific free operations */
      case BGP_MP_REACH_NLRI:
      case BGP_MP_UNREACH_NLRI:
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
  if (attributes->mp_unreach_nlri) {
    mrt_free_nlri(&(attributes->mp_unreach_nlri->l), TRUE);
    free(attributes->mp_unreach_nlri);
  }
  if (attributes->trace) free(attributes->trace);
  free(attributes);
  return;
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
      break;
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

