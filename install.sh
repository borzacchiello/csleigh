#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd "$SCRIPT_DIR"

if [ "$1" == "-f" ]; then
    rm -rf build
    rm processors/**/*.sla
fi

[ -d build ] || mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
make -j12 || exit 1

./sleigh_builder -a ../processors
[ -d /usr/local/share/sleigh ] || sudo mkdir /usr/local/share/sleigh

sudo cp -r ../processors /usr/local/share/sleigh
sudo make install

popd
