# Contributing

## Development Setup

- Windows (required for runtime behavior and ETW integration)
- Rust stable toolchain

From repository root:

```powershell
cd Vigil
cargo check
cargo test
```

## Code Quality Requirements

Before opening a PR:

```powershell
cd Vigil
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-targets --all-features
```

## Pull Request Guidelines

- Keep changes focused and scoped.
- Include tests for behavioral changes.
- Update docs (`README.md`, `SECURITY.md`, config examples) when behavior changes.
- Describe operational impact (privileges, runtime requirements, log format changes).

## Commit Guidance

- Use clear commit messages with intent and impact.
- Avoid mixing refactors with functional changes unless tightly related.

## Security-Sensitive Areas

Extra care is required for:

- `Vigil/src/wintrust.rs`
- `Vigil/src/etw.rs`
- `Vigil/src/engine.rs`

For these files, PR descriptions should explain threat model and false-positive/false-negative impact.
