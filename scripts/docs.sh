SCRIPTDIR=$PWD
PALLET=${1:-"merkle"}

cd "$SCRIPTDIR/pallets/$PALLET/" && cargo doc --open --no-deps