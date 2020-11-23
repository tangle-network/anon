#!/bin/bash
SCRIPTDIR=$PWD
for d in $(ls -d ./pallets/*/) ; do
    cd "$SCRIPTDIR/$d" && sudo cargo test
done