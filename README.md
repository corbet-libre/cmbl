# cmbl — Assembly

Admission-pass candidate in progress, uncompiled and unqualified. No live room
or authenticated issuance endpoint acceptance is claimed.

## Scope

Blind volatile ordering and bounded encrypted relay for public rooms. Store opaque room IDs, ordering counters, expiring connection handles and ciphertext only. No member identity, attendance link, roster, MLS tree, profile or content. Admission-only RFC9474 passes hide rooms during issuance. Members enforce MLS membership, counter and fork size; Assembly only orders and relays. No Wave or ledger debit for joining.

## Validation

Stable native and actual wasm vectors; exact 100% line and branch coverage on
nightly LLVM. Current green status must come from the exact CI run, never from
this contract. Expensive room load tests use owned CI and real Tor when the
lower layers are ready. See [Contract](docs/CONTRACT.md).

## Reuse

Use existing key, guard, MLS, Link and volatile storage owners. Serde and
thiserror provide formats and bounded errors. No own cryptographic primitives.
