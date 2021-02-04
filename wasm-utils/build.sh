chmod +x init.sh
./init.sh

wasm-pack build --out-name mixer-client && cp -R ./pkg/* ../web/mixer-client