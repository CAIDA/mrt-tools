#!/bin/bash

# MRT record file contains less than a complete MRT header

../src/firstmrt 2>&1 < short-header.mrt |grep ^ERROR > test.$$
cmp short-header.output test.$$
if [ "$?" = "0" ] ;then
  echo "OK properly detected short-header MRT record"
  rm -f test.$$
  exit 0
fi 
rm -f test.$$
diff -u short-header.output test.$$
echo "FAIL: short-header MRT record not detected as expected"
exit 1
