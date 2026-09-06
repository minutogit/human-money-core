// Auto-generated wasm gate for l2_client_simulator
// On wasm32 the tokio+reqwest based simulator is unavailable – provide stub
#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("l2_client_simulator not supported on wasm32-unknown-unknown");
}

#[cfg(not(target_arch = "wasm32"))]
include!("inner_main.rs");
