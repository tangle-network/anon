SCRIPTDIR=$PWD
PALLET=${1:-"merkle"}

for d in $(ls -d ./pallets/$PALLET/) ; do
    cd "$SCRIPTDIR/$d" && cargo doc --open --no-deps
done