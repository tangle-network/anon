const isServer = () => typeof window === 'undefined';

function Index() {
	if (!isServer()) {
		import("merkle-client").then(wasm => {
			let cl = wasm.MerkleClient.new(2);
			let note = cl.generate_note();
			console.log(note, note.length);
			let leaf = cl.save_note(note);
			console.log(leaf);
			cl.save_note_to_storage(note);

			cl.add_leaves([leaf]);
			let root = cl.get_root();
			let proof = cl.generate_proof(root, leaf);
			console.log(proof);
		});
	}
	return "hello there";
}

export default Index;