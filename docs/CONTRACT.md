# Contract

Blind volatile ordering and bounded encrypted relay for public rooms. Store opaque room IDs, ordering counters, expiring connection handles and ciphertext only. No member identity, attendance link, roster, MLS tree, profile or content. Anonymous permits and restart/handover proof verification must be independently reviewed; missing proof support refuses operations.

Production integration remains blocked until verified owner capabilities exist.
Independent transition tests never establish permit unlinkability, MLS, Tor,
restart proof correctness or end-to-end acceptance.

## Current API

`Assembly<Store>` consumes the existing cmmr Store port, supplied through cvtl;
there is no parallel persistence implementation. Requests bind opaque room and
operation IDs. Resume requires an authenticated member-carried counter. CAS
serializes changes; same-operation replay returns the recorded outcome and a
changed request under the same operation is refused. Every record expires.
Connection handles are anonymous room-local random values, never attendance,
member, device or transport identity. Losing the last connection forgets state.

`Permit` has no public constructor or deserializer. `UnavailableProofs` refuses
all production operations. The previous forum permit code depends on durable
allocation and old identity contracts; it is not reused as a room proof.
`handover` also refuses until reviewed size/lineage/72-hour evidence exists.
Internal tests supply prevalidated capability preconditions to exercise real
Memory CAS, byte retention, expiry, restart and bounds. They are NOT evidence
of anonymous permit correctness, counter-recovery proof or real-Tor delivery.

Open: reviewed anonymous room authorization, counter-resumption and listing
handover constructions; reader acknowledgements/relay fan-out wiring to Link;
real Valkey adapter integration and LT-ROOMS. No full room acceptance claimed.

`Action::Read { after }` returns a bounded batch of opaque `RelayFrame`s plus
`through` and an explicit `gap` when earlier ciphertext has expired. Reads do
not renew retention or create per-reader/attendance records. Relay sequence is
independent from the ordered-commit counter. A connection renewal never extends
a retained frame's original expiry. Link owns fan-out, retransmission and
acknowledgements; delivery is at least once, and Threads owns message replay
rejection. Operation receipts are bounded by the caller-supplied limit and expire with
their authenticated permit. A retained operation replays its original outcome
and rejects changed bytes even after intervening writes. Capacity refuses new
mutations rather than evicting still-valid receipts. Loss of all anonymous
connections forgets counters, frames and receipts; verified resumption is then
required. No permanent replay ledger or server-side history is introduced.
