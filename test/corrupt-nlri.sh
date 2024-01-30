#!/bin/bash

../src/bgp-explain 2>&1 < corrupt-nlri.mrt |grep ^ERROR > test.$$
cmp corrupt-nlri.output test.$$
if [ "$?" = "0" ] ;then
  echo "OK properly detected corrupt NLRI MRT record"
  rm -f test.$$
  exit 0
fi 
diff -u corrupt-nlri.output test.$$
echo "FAIL: corrupt NLRI in MRT record not detected as expected"
rm -f test.$$
exit 1
