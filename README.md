```Usage: bgp-explain [OPTION...] 
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
