# Agent instructions

English comments and documentation. Preserve README Scope and docs/CONTRACT.md.
Blind volatile ordering and bounded encrypted relay for public rooms. Store opaque room IDs, ordering counters, expiring connection handles and ciphertext only. No member identity, attendance link, roster, MLS tree, profile or content. Anonymous permits and restart/handover proof verification must be independently reviewed; missing proof support refuses operations.

No workstation Cargo, including fmt/metadata. Public CI runs stable quality,
actual wasm vectors and strict 100% line/branch coverage. Expensive tests belong
to owned CI. No forged capability or unavailable proof may pass production.
Dependabot Cargo/Actions and main first-party dependencies; one locked revision.
Explicit file staging, plain English commits, no AI attribution, registry
publication, secrets or private operational details in repository content.
