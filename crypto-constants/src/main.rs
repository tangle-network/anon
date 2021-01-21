pub mod poseidon;
#[cfg(feature = "std")]
mod utils;

fn main() {
	#[cfg(feature = "std")]
	utils::print_constants();
}
