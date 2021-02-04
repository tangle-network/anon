if ! command -v wasm-pack &> /dev/null
then
    echo "wasm-pack not be found"
    echo "install wasm-pack..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
else
	echo "wasm-pack exists"
fi