/* addresses.h
 */

#ifndef ADDRESSES_H
#define ADDRESSES_H

#include <endian.h>
#include <stdint.h>
#include <inttypes.h> /* PRIu8 */
#ifdef DPDK
#include <rte_ether.h>
#include <rte_ip.h>
#endif

/* IPv6 Header */

struct ipv6_address {
    union {
        uint8_t ad[16];
        struct {
            uint64_t network;
            uint64_t host;
        };
        struct {
            uint64_t upper;
            uint64_t lower;
        };
        __uint128_t whole;
    };
} __attribute__ ((__packed__));

/* printf() macros */
#define PRI_IPV6 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define PRI_IPV6_V(x) x.ad[0], x.ad[1], x.ad[2], x.ad[3], \
                      x.ad[4], x.ad[5], x.ad[6], x.ad[7], \
                      x.ad[8], x.ad[9], x.ad[10], x.ad[11], \
                      x.ad[12], x.ad[13], x.ad[14], x.ad[15]

/* printf(PRI_IPV6 "\n", PRI_IPV6_V(ip_address)); */

struct ipv6_header {
    union {
        struct {
#           if __BYTE_ORDER == __LITTLE_ENDIAN
            /* GCC on little endian systems fills bits from low to high order
             * but network protocols go the opposite way
             */
            uint8_t dscp_high: 4;
            uint8_t version: 4;
            uint8_t flow_label_high: 4;
            uint8_t ecn: 2;
            uint8_t dscp_low: 2;
#           else // __BIG_ENDIAN
            uint8_t version: 4;
            uint8_t dscp_high: 4;
            uint8_t dscp_low: 2;
            uint8_t ecn: 2;
            uint8_t flow_label_high: 4;
#           endif // __BIG_ENDIAN
            uint16_t flow_label_low;
            uint16_t payload_len;  
            uint8_t  proto;        
            uint8_t  hop_limits;   
            struct ipv6_address src;
            struct ipv6_address dst;
        } __attribute__((__packed__));
#       ifdef DPDK
        struct ipv6_hdr dpdk;
#       endif
    };
} __attribute__((__packed__));

/* IPv4 header */

struct ipv4_address {
    union {
        uint8_t ad[4];
        uint32_t whole;
    };
} __attribute__ ((__packed__));

struct ipv4_header {
    union {
        struct {
#           if __BYTE_ORDER == __LITTLE_ENDIAN
            /* GCC on little endian systems fills bits from low to high order
             * but network protocols go the opposite way
             */
            union {
                struct {
                    uint8_t  length: 4;
                    uint8_t  version: 4;
                } __attribute__ ((__packed__));
                uint8_t version_ihl;
            };
            union {
                struct {
                    uint8_t ecn: 2;
                    uint8_t dscp: 6;
                } __attribute__ ((__packed__));
                uint8_t  type_of_service;       
            };
            uint16_t total_length;          
            uint16_t packet_id;             
            union {
                struct {
                    uint8_t fragoff_high: 5;
                    uint8_t more_fragments: 1;
                    uint8_t dont_fragment: 1;
                    uint8_t frag_reserved: 1;
                    uint8_t fragoff_low;
                } __attribute__ ((__packed__));
                uint16_t fragment_offset;       
            };
#           else // __BIG_ENDIAN
            union {
                struct {
                    uint8_t  version: 4;
                    uint8_t  length: 4;
                } __attribute__ ((__packed__));
                uint8_t version_ihl;
            };
            union {
                struct {
                    uint8_t dscp: 6;
                    uint8_t ecn: 2;
                } __attribute__ ((__packed__));
                uint8_t  type_of_service;       
            };
            uint16_t total_length;          
            uint16_t packet_id;             
            union {
                struct {
                    uint8_t frag_reserved: 1;
                    uint8_t dont_fragment: 1;
                    uint8_t more_fragments: 1;
                    uint8_t fragoff_high: 5;
                    uint8_t fragoff_low;
                } __attribute__ ((__packed__));
                uint16_t fragment_offset;       
            };
#           endif // __BIG_ENDIAN
            uint8_t  time_to_live;          
            uint8_t  next_proto_id;         
            uint16_t hdr_checksum;          
            struct ipv4_address src;
            struct ipv4_address dst;
        } __attribute__ ((__packed__));
#       ifdef DPDK
        struct ipv4_hdr dpdk;
#       endif
    };
} __attribute__ ((__packed__));

/* printf() and scanf() macros */
#define PRI_IPV4 "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define SCN_IPV4 "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8

#define PRI_IPV4_V(x) x.ad[0], x.ad[1], x.ad[2], x.ad[3]
#define SCN_IPV4_V(x) x.ad+0, x.ad+1, x.ad+2, x.ad+3

/* printf ("IP: " PRI_IPV4 "\n", PRI_IPV4_V(ipv4_address));
 * sscanf("192.168.1.1", SCN_IPV4, SCN_IPV4_V(ipv4_address));
 */

/* Ethernet headers and types in network byte order */

struct ethernet_address {
    union {
        uint8_t ad[6];
        uint64_t whole: 48 __attribute__ ((__packed__));
#       ifdef DPDK
        struct ether_addr dpdk;
#       endif
    };
} __attribute__ ((__packed__));

struct ethernet_header {
    union {
        struct {
            struct ethernet_address dst;
            struct ethernet_address src;
            uint16_t type;
        };
#       ifdef DPDK
        struct ether_hdr dpdk;
#       endif
    };
} __attribute__ ((__packed__));

struct ethernet_header_1vlan {
    union {
        struct {
            struct ethernet_address dst;
            struct ethernet_address src;
            uint16_t vlan_ethertype;     // ETHERTYPE_NBO_VLAN
            uint16_t vlan;
            uint16_t type;
        };
#       ifdef DPDK
        struct {
            struct ether_hdr dpdk;
            struct vlan_hdr dpdk_vlan;
        };
#       endif
    };
} __attribute__ ((__packed__));

struct icmp_destination_unreachable {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t unused;
    uint16_t mtu;
    uint8_t original_packet[];
} __attribute__ ((__packed__));


// NBO means Network Byte Order (Big Endian)

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define ETHERTYPE_NBO_IPv4 0x0008
#define ETHERTYPE_NBO_IPv6 0xDD86
#define ETHERTYPE_NBO_ARP  0x0608
#define ETHERTYPE_NBO_RARP 0x3580
#define ETHERTYPE_NBO_VLAN 0x0081
#define ETHERTYPE_NBO_QINQ 0xA888
#define ETHERTYPE_NBO_ETAG 0x3F89
#define ETHERTYPE_NBO_1588 0xF788
#define ETHERTYPE_NBO_SLOW 0x0988
#define ETHERTYPE_NBO_TEB  0x5865
#define ETHERTYPE_NBO_LLDP 0xCC88
#define ETHERTYPE_NBO_MPLS 0x4788
#define ETHERTYPE_NBO_MPLSM 0x4888

#else // __BIG_ENDIAN

#define ETHERTYPE_NBO_IPv4 0x0800 
#define ETHERTYPE_NBO_IPv6 0x86DD 
#define ETHERTYPE_NBO_ARP  0x0806 
#define ETHERTYPE_NBO_RARP 0x8035 
#define ETHERTYPE_NBO_VLAN 0x8100 
#define ETHERTYPE_NBO_QINQ 0x88A8 
#define ETHERTYPE_NBO_ETAG 0x893F 
#define ETHERTYPE_NBO_1588 0x88F7 
#define ETHERTYPE_NBO_SLOW 0x8809 
#define ETHERTYPE_NBO_TEB  0x6558 
#define ETHERTYPE_NBO_LLDP 0x88CC 
#define ETHERTYPE_NBO_MPLS 0x8847 
#define ETHERTYPE_NBO_MPLSM 0x8848 

#endif // __BIG_ENDIAN

#endif /* ADDRESSES_H */
