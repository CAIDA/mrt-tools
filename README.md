MRT Dissection Tool

The Internet backbone uses the Border Gateway Protocol (BGP) to distribute
network routing information (instructions where to send packets next)
throughout the worldwide network. Groups such as Routeviews and RIPE RIS
capture the raw BGP update messages sent by some of these Internet routers
and store them in something called the Multithreaded Routing Toolkit (MRT)
format documented in Internet standard RFC 6396. This captured data allows
both academic researchers and Internet operators to investigate and analyze
how the Internet actually constructed itself as a result of the chaotic
operation of the BGP system.

Unfortunately, the data is sometimes bad.

Data corruption sneaks into MRT files from sources including storage errors
and software bugs. If not detected and understood, data corruption can impair
analysis and lead to incorrect results.

The MRT dissection tool published at
https://gitlab.caida.org/herrin/mrt-tools does two things. First, it allows
both the collectors of BGP data and the users of MRT files to check those
files for data corruption before use. As a program written in C, it is fast
and efficient enough to do so without impairing the normal collection
pipeline.

Second, the dissection tool helps investigators trace suspicious data reported
from an MRT file back to the original binary bytes in the BGP update message.
It then offers links back to the relevant Internet standards which explain
how each byte is to be interpreted. This helps a researcher understand whether
an unexpected result from other MRT tools is actually corrupt or just
unexpected. 



```
Usage: bgp-explain [OPTION...] 
read and explain the contents of a BGP MRT file received from stdin

  -b, --bad                  Only display MRT records containing errors.
  -c, --count                Suppress record output. Count the number of bad,
                             correct and total MRT entries. Return non-zero if
                             the file contains at least one bad MR entry.
  -e, --explain              Verbosely explain the contents of each MRT
                             record.
  -q, --quiet                Trace but do not verbosely explain errors in MRT
                             records.
  -t, --trace                Trace decoded MRT record to the bytes in the file.
                            
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

Example of detected corrupt data from a January 2022 Routeviews MRT file:

```
$ bzcat updates.20220114.2030.bz2 | bgp-explain --bad --explain |more
1642192201.032958(byte 3888): peer AS57695 (206.126.236.214)
  withdrawn bytes 0, attribute bytes 51, nlri bytes 8, IPv4
[...]
    Prefix: 0.0.0.0/0
        60: 7eec d6c0 0808 0c97 0378 e15f 32c8 0000
        70: 000c 1768 7182
            ^^
        80:
Information: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
Network Layer Reachability Information
[uint8 prefix length][0 or more bytes, minimum needed for the prefix len]
e.g. /0 needs 0 bytes, /15 needs 2, /17 needs 3, /24 needs 3, /25 needs 4.

    Prefix: 23.104.0.0/12
ERROR: NLRI IPv4 prefix 23.104.0.0/12 is wrong. Would be 23.96.0.0/12
  in MRT record at file position 3888
        60: 7eec d6c0 0808 0c97 0378 e15f 32c8 0000
        70: 000c 1768 7182
              ^^ !!!!
    Prefix: 0.0.0.0/113
ERROR: NLRI prefix length 113 requires 15 bytes but only has 1
  in MRT record at file position 3888
        70: 000c 1768 7182
                      !!^^ oooo oooo oooo oooo oooo
        80:
            oooo oooo
Information: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
Network Layer Reachability Information
[uint8 prefix length][0 or more bytes, minimum needed for the prefix len]
e.g. /0 needs 0 bytes, /15 needs 2, /17 needs 3, /24 needs 3, /25 needs 4.
```

In this instance, a BGP “addpath” update message was incorrectly recorded as
a normal BGP update message due to a software bug in the collector.
“Addpath” inserts four bytes of identifying information in front of each
network route. Because it was identified as a normal update message, these
bytes were incorrectly interpreted as additional routes, and the actual
route later in the message was miscomputed. The correct route was encoded
in the bytes 17 68 71 82, which according to the decoding instructions output
by the tool translates to 104.113.130.0/23.

