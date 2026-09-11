# Native semantic analysis

Rust imports and reexports are parsed with `syn`. JavaScript, TypeScript and JSX
use the exactly locked Oxc parser; the auditor does not require Node.js.
Multiline and grouped syntax receives the same domain and component boundary
checks as single-line syntax. Comments and literal strings do not create imports.

Vite checks inspect exported configuration syntax, including quoted keys,
computed literal keys, CommonJS exports and multiline values. Unrelated objects
and strings are not configuration. These checks do not execute configuration or
resolve arbitrary runtime values.

Malformed required syntax returns an incomplete-analysis error before the AST
pilot can supply findings. Consumers must propagate the result from
`run_ast_pilot`; a parse failure must not become an empty successful analysis.
Vite's standalone diagnostic findings also retain the parse failure.

Contributor verification:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
bash scripts/ci-local.sh required
```

`tests/semantic_boundary_pairs.rs` contains unsafe cases, safe counterparts,
formatting equivalents, inert lookalikes and malformed-input controls. Browser
storage and tool-routing pairs remain independent: declarations and imported
receipts cannot establish trusted execution.
