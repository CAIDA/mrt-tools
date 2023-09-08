#!/bin/bash

../src/firstmrt 2>&1 < short.mrt |grep ^ERROR > test.$$
cmp short.output test.$$
if [ "$?" = "0" ] ;then
  echo "OK properly detected short MRT record"
  rm -f test.$$
  exit 0
fi 
rm -f test.$$
diff -u short.output test.$$
echo "FAIL: short MRT record not detected as expected"
exit 1
