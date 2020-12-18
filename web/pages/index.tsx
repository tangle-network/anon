function Index() {
	import("../wasm-utils/pkg").then(module => module.greet());
	return "hello there";
}

export default Index;