const isServer = () => typeof window === 'undefined';

function Index() {
	import("../wasm-utils").then(module => {
		if (!isServer()) {
			let cl = module.MerkleClient.new(2);
			let arr = cl.generate_secrets_and_save();
			let leaf = arr[2];
			cl.load_secrets_from_storage();

			cl.add_leaves([leaf]);
			let root = cl.get_root();
			let proof = cl.generate_proof(root, leaf);
			console.log(proof);
		}
	});
	return "hello there";
}

export default Index;