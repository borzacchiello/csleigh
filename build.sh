#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

pushd "$SCRIPTPATH" || exit 1

[ -d "$SCRIPTPATH/build" ] \
    || mkdir "$SCRIPTPATH/build"

pushd "$SCRIPTPATH/build"           || exit 1
cmake -DCMAKE_BUILD_TYPE=Release .. || exit 1
make -j`nproc`                      || exit 1
popd

./build/sleigh -a ./processors
popd
