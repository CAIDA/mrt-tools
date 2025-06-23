#!/bin/bash

# rm entries* hashfile*

while IFS= read -r FILE ;do
  echo "$FILE"
  bzcat ${FILE} | src/compresspoc --quiet > out.txt
  R=$?
  if [ "$R" != "0" ] ;then
    echo "failed with $R"
    exit $R
  fi
done < mrt-update-files.list
exit 0
