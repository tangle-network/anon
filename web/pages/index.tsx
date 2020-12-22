function Index() {
	import("../wasm-utils").then(module => module.greet());
	return "hello there";
}

export default Index;