#!/bin/bash

set -e -v

INCLUDE=$(gcc -E -Wp,-v -xc /dev/null 2>&1 | \
  sed -n '/#include </,/search list/p' | grep '^ ')
INCLUDE=$(echo ${INCLUDE} | sed 's/ / -I/g')

#LINENO=$(cat -n Makefile | grep '\s# Automatically added by makedepend' |\
#  awk '{ print $1 }')
#echo $INCLUDE
#echo $LINENO

rm -f makedepend.tmp
touch makedepend.tmp
makedepend -I${INCLUDE} -fmakedepend.tmp -w99999 \
  -s"# Automatically added by makedepend after this line" *.c
# get rid of references to system include files since we don't want
# local machine include files propagating into the Makefile save in 
# git
sed 's| /[^ ]*||g' makedepend.tmp |grep -v "\.o:[\s]*$" > Makefile.depend
rm makedepend.tmp
