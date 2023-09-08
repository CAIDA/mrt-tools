#!/bin/bash

../src/firstmrt 2>&1 < corrupt-nlri.mrt |grep ^ERROR > test.$$
cmp corrupt-nlri.output test.$$
if [ "$?" = "0" ] ;then
  echo "OK properly detected corrupt NLRI MRT record"
  rm -f test.$$
  exit 0
fi 
rm -f test.$$
diff -u corrupt-nlri.output test.$$
echo "FAIL: corrupt NLRI in MRT record not detected as expected"
exit 1
