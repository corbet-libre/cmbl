# Agent instructions

English comments and documentation. Preserve README Scope and docs/CONTRACT.md.
Blind volatile ordering and bounded encrypted relay for public rooms. Store opaque room IDs, ordering counters, expiring connection handles and ciphertext only. No member identity, attendance link, roster, MLS tree, profile or content. The reviewed room pass proves admission only: no ledger debit. Members enforce MLS membership, counter and fork size; Assembly never accepts those as server authority. Keep actual RFC9474 verification and authenticated issuance routing/quota separate; no accepting substitute.

No workstation Cargo, including fmt/metadata. Public CI runs stable quality,
actual wasm vectors and strict 100% line/branch coverage. Expensive tests belong
to owned CI. No forged capability or unavailable proof may pass production.
Dependabot Cargo/Actions and main first-party dependencies; one locked revision.
Explicit file staging, plain English commits, no AI attribution, registry
publication, secrets or private operational details in repository content.
