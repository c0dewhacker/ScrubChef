# 🔪 ScrubChef

**Local-first log redaction, cooked with precision.**

ScrubChef is a specialized tool designed for security engineers and developers to safely prepare logs, traces, and documents for sharing. It targets and removes sensitive data (PII, secrets, infrastructure details) entirely within the browser, ensuring your data never touches a server.

## 🛡️ Security Principles
Redaction is a high-stakes task. ScrubChef is built on three core pillars:
1. **Zero Data Leakage**: By using a Rust-to-WASM engine, all sensitive processing happens on your machine.
2. **Auditability**: Every redaction is deterministic and can be inspected stage-by-stage.
3. **Reversibility**: Generates a secure sidecar mapping for reverse lookups when troubleshooting requirements change. The sidecar holds the original values in clear text — keep it separate from the redacted output.

## 🚀 Key Features
- **WASM Under the Hood**: High-performance detection logic written in Rust.
- **Composable Pipelines**: Build complex redaction recipes by chaining detectors.
- **Deep Inspection**: Use "Eye" mode to see exactly what each stage of your pipeline modified.
- **Standalone Distribution**: Builds into a single, portable HTML file with zero dependencies.

## 🏗️ Project Structure
- `/engine`: Rust source for the redaction core.
- `/ui`: React + TypeScript frontend powered by Vite.

## 🛠️ Development & Building

### Prerequisites
- [Rust](https://rustup.rs/) 1.85+ (with `wasm-pack`)
- [Node.js](https://nodejs.org/) (current LTS)

### Full Build (Single HTML File)
1. **Build the Engine**:
   ```bash
   cd engine && wasm-pack build --target web
   ```
2. **Setup the UI**:
   ```bash
   cd ui && npm install
   ```
3. **Generate standalone site**:
   ```bash
   cd ui && npm run build
   ```
   *Result: A single `index.html` file in `ui/dist` containing the entire application.*

### Tests & Checks
```bash
cd engine && cargo test                                   # engine unit tests
cd engine && cargo clippy --all-targets -- -D warnings     # catches non-compiling detectors
cd ui && npm run lint
cd ui && npm run build                                    # also typechecks
```

## ⚖️ Disclaimer
While ScrubChef is powerful, automated redaction is not a replacement for human review. Always verify the output before sharing sensitive materials.

## 📄 License
[MIT](LICENSE) © c0dewhacker

