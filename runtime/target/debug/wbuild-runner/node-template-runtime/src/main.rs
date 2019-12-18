
				use substrate_wasm_builder::build_project_with_default_rustflags;

				fn main() {
					build_project_with_default_rustflags(
						"/Users/drewstone/code/commonwealth/pure-zk/runtime/target/debug/build/node-template-runtime-d47bf45274b95110/out/wasm_binary.rs",
						"/Users/drewstone/code/commonwealth/pure-zk/runtime/Cargo.toml",
						"-Clink-arg=--export=__heap_base",
					)
				}
			