# Voucher Standard Builder

Browser-based offline-first web tool for visual configuration, CEL validation, and Ed25519 cryptographic signing of `VoucherStandardDefinition` files (`standard.toml`).

## Architecture

- **Core WASM Bridge (`bindings/wasm/`)**: Pure Rust logic compiled to WebAssembly via `wasm-pack`. Exposes cryptographic functions (`Ed25519`, `BIP-39`, `did:key`), canonical TOML serialization, standard verification, and `cel-interpreter` syntax compilation.
- **Frontend App (`tools/standard-builder/`)**: Vite + React single-page app utilizing the local `human_money_wasm` npm package.
- **Zero Server Overhead**: 100% offline-first execution in browser memory. Key seeds are processed in WASM RAM and never stored in `localStorage` or disk.

## Setup & Running Locally

1. **Build WASM Bridge:**
   ```bash
   cd bindings/wasm
   npx wasm-pack build --target web
   ```

2. **Run Standard Builder Frontend:**
   ```bash
   cd tools/standard-builder
   npm install
   npm run dev
   ```

3. Open `http://localhost:3000` in your browser.

## Build Production Bundle

```bash
cd tools/standard-builder
npm run build
```
