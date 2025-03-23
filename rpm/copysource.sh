#!/bin/sh

SOURCEDIR=$1
DESTDIR=$2

umask 022
rm -rf ${DESTDIR}
mkdir -p ${DESTDIR}
cd ${SOURCEDIR}
tar --exclude="rpm/[A-Z]*" -cpf  ${DESTDIR}/source.tar .
cd ${DESTDIR}
tar -xpf source.tar
rm source.tar
exit 0

