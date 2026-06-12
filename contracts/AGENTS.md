# contracts Agent Instructions

This cell owns the contract index that maps each analyzer evidence artifact to
its canonical wire contract. The contracts themselves are the JSON Schemas under
[`schemas/`](../schemas/); this directory documents and routes them.

- Owns: `contracts/README.md` (the artifact-to-schema index) and the discipline
  that every analyzer output is validated against its matching schema in
  [`schemas/`](../schemas/) before it is published.
- Forbidden: hand-mirroring a schema's shape in consumer code, publishing an
  evidence artifact that has not been validated against its schema, or making a
  breaking schema change without bumping `schema_version`.
- Proof lane: generation / drift checks — `just api-drift` (public-API and
  semver drift) plus the schema validation each analyzer runs before emitting an
  artifact.

A breaking change to any schema is gated by the public-API / semver drift lane;
bump the `schema_version` and update the matching row in `contracts/README.md`.
