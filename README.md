# cmbl — Assembly

Implementation in progress. No production success is available without the
required verified lower-layer capabilities.

## Scope

### Purpose

cmbl is the server side of public rooms: it orders joins and relays encrypted messages while learning only connection count and traffic volume.

### Owns

- One volatile ordering counter per opaque room ID, ordering joins and encrypted commits.
- Bounded relay of encrypted room messages.
- Room-pass and listing handover between forks: after 72 hours the larger fork keeps the listing, a tie goes to the older lineage.
- Resuming order after a restart from verified member state.

### Never

- Learns who is in a room or what is said: no identities, membership lists, member-to-room links, cross-room graph, or content. The only accepted disclosure is active-connection count and traffic volume per room.
- Stores group state, message keys, plaintext, permanent counters, or traffic history; relays without a valid scoped pass; or trusts a client-claimed counter or size.
- Provides admins, kick controls, or a removal operation.
- Stores messages for later delivery; there is no mailbox.
- Performs accounting; joining carries no charge.

### States

Absent, Active (ordering counter plus expiring connection, relay, and pass state), conflicting order requiring retry, and awaiting verified resume after a restart. Disconnect or expiry removes volatile state.

### Test obligations

- Concurrent joins converge on one order; replayed, foreign, or expired passes and forged handovers fail.
- All retained server state is limited to the accepted room metadata and bounded opaque protocol state.
- Losing all connections or restarting cannot replay an old transition or disclose a roster.
- Room load scenarios cover a ramped room, a join storm converging on one epoch with bounded retries, a large simultaneous connection count within CPU and renewal budgets, and restart recovery restoring ordering from members without new disclosure.
- Listing handover follows the larger fork after 72 hours, with ties going to the older lineage.
- Pass, resumption, and permit-unlinkability evidence is independently reviewed; missing proof support refuses the operation.

## Validation

Stable native and actual wasm vectors; exact 100% line and branch coverage on
nightly LLVM. Current green status must come from the exact CI run, never from
this contract. Expensive room load tests use owned CI and real Tor when the
lower layers are ready. See [Contract](docs/CONTRACT.md).

## Reuse

Use existing key, guard, MLS, Link and volatile storage owners. Serde and
thiserror provide formats and bounded errors. No own cryptographic primitives.
