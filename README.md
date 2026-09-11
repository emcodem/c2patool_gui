# C2PA Inspector

A desktop GUI for viewing the **full, detailed** C2PA/Content Credentials report for a file —
the same level of detail as `c2patool --detailed` (cert chains, COSE signature info, assertion
store, validation results), not just the human-readable summary that most C2PA viewers show.

Built with [Tauri](https://tauri.app) (Rust + React/TypeScript), and ships as a **single
portable binary per platform** — `c2patool` is embedded directly in the executable at compile
time and extracted to a per-user cache directory on first use. No separate install, no bundled
installer, no dependency on the user having `c2patool` on their `PATH`.

## Features

- **JSON tree view** of the full detailed manifest report, with filtering and click-to-expand.
- **Validation summary**: translates `validation_results` codes into plain language, sourced
  verbatim from the official [C2PA specification's Standard Status Codes table](https://spec.c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_standard_status_codes)
  (`src/validationCodes.ts`). Clarifies that `validation_state: Valid` only reflects
  structural/cryptographic integrity — it does **not** mean the signer is trusted.
- **Click a validation entry** to jump to and highlight the corresponding node in the JSON tree.
- **Signer identity inline**: each manifest row shows the signer's `common_name` (issuer on hover).
- **Configurable trust anchors**: a "Trust Sources" panel lets you enable/disable/add PEM
  sources (URL or local file) used for signature trust validation. Ships with two defaults,
  both enabled: the official C2PA trust list and Sony's published trust anchor.
- **Copy JSON** button to copy the full report to the clipboard.

## Development

Prerequisites: Node.js 22+, Rust (stable, via [rustup](https://rustup.rs)). On Windows you also
need the MSVC C++ build tools (Visual Studio Build Tools with the "Desktop development with
C++" workload).

```sh
npm install
npm run tauri dev
```

## Building a release binary

```sh
npm run tauri build -- --no-bundle
```

`--no-bundle` skips installer generation (MSI/NSIS/DMG) — the app is meant to be distributed as
a single portable executable, not installed. The output binary is at:

- Windows: `src-tauri/target/release/tauri-app.exe`
- macOS (universal, both Intel and Apple Silicon): add `--target universal-apple-darwin`;
  output at `src-tauri/target/universal-apple-darwin/release/tauri-app`

Note: a macOS binary can only be built on macOS (or via the CI workflow below) — Tauri cannot
cross-compile a macOS app from Windows or Linux.

## Testing

```sh
cargo test --manifest-path src-tauri/Cargo.toml
```

The `embedded_c2patool_analyzes_sample` test extracts the embedded `c2patool` binary to a temp
directory and runs it against `samples/C.jpg`, asserting the JSON report is correct. This is the
real functional check that the "single embedded binary" approach actually works on a given
OS/architecture — as opposed to a GUI smoke test, which only proves the app window doesn't crash
on launch.

## CI / Releases

`.github/workflows/build.yml` builds portable binaries for Windows and macOS (universal) on every
push to `main` and on `v*` tags. Each platform build runs:

1. The functional test above (proves the embedded binary actually works).
2. A GUI smoke test (launches the built app and confirms it stays alive for 5s — proves the
   WebView/frontend initializes, but does **not** exercise any specific feature).

Pushing a `v*` tag additionally publishes a GitHub Release (non-draft, marked "latest") with both
binaries attached.

**macOS distribution caveat**: the released binary is not code-signed or notarized. A user
downloading it via a browser will hit Gatekeeper ("app is damaged" / unidentified developer) and
needs to right-click → Open the first time, or run `xattr -cr` on it. Proper signing requires an
Apple Developer account.

## Project layout

- `src-tauri/binaries/` — the embedded `c2patool` binaries (Windows x64, macOS universal), named
  with their target triple per Tauri convention. These are compiled into the app via
  `include_bytes!` in `src-tauri/src/lib.rs`.
- `src-tauri/src/trust.rs` — trust-anchor source management (fetching, merging, persisting).
- `samples/` — signed/unsigned sample assets from c2patool's own test fixtures, used for manual
  testing and the automated functional test.
