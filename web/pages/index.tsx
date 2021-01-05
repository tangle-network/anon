const isServer = () => typeof window === 'undefined';

function Index() {
	if (!isServer()) {
		import("../merkle-client").then(wasm => {
			let cl = wasm.Mixer.new([["EDG", 0, 2]]);
			let note = cl.generate_note("EDG", 0);
			console.log(note, note.length);
			let leaf = cl.save_note(note);
			console.log(leaf);
			cl.save_note_to_storage(note);

			cl.add_leaves("EDG", 0, [leaf]);
			let root = cl.get_root("EDG", 0);
			let proof = cl.generate_proof("EDG", 0, root, leaf);
			console.log(proof);
		});
	}
	return "hello there";
}

export default Index;