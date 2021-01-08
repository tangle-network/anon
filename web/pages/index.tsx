const isServer = () => typeof window === 'undefined';

function Index() {
	if (!isServer()) {
		import("../mixer-client").then(wasm => {
			let cl = wasm.Mixer.new([["EDG", 0, 32]]);
			let note = cl.generate_note("EDG", 0, 123);
			console.log(note, note.length);
			let data = cl.save_note(note);
			let leaf = data.get("leaf");
			let asset = data.get("asset");
			let id = data.get("id");
			let block_number = data.get("block_number");
			console.log(leaf, asset, id, block_number);
			cl.save_note_to_storage(note);
			cl.load_notes_from_storage();

			cl.add_leaves("EDG", 0, [leaf]);
			let root = cl.get_root("EDG", 0);
			let proof = cl.generate_proof("EDG", 0, root, leaf);
			console.log(proof);
		});
	}
	return "hello there";
}

export default Index;