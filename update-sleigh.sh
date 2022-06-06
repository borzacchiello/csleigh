#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

pushd "$SCRIPTPATH" || exit 1

if [ -d /tmp/ghidra ]; then
    echo "/tmp/ghidra exists. Delete it"
    exit 1
fi

git clone --depth 1 https://github.com/NationalSecurityAgency/ghidra.git /tmp/ghidra

pushd /tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp || exit 1
cat<<EOT >> Makefile
sleigh_src:
	mkdir -p sleigh_src
	cp \$(LIBSLA_SOURCE) Makefile sleigh_src
EOT
make sleigh_src || exit 1
popd

cp /tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_src/* ./sleigh
cp -r /tmp/ghidra/Ghidra/Processors/* ./processors

popd
