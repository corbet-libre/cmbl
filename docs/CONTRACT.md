# Contract

Blind volatile ordering and bounded encrypted relay for public rooms. Store opaque room IDs, ordering counters, expiring connection handles and ciphertext only. No member identity, attendance link, roster, MLS tree, profile or content. The reviewed room pass proves community admission only. Members enforce MLS membership, latest group state and fork size; Assembly does not receive a roster.

The new pass candidate is uncompiled. Independent storage transition tests never establish permit unlinkability, MLS, Tor or end-to-end acceptance.

## Current API

`Assembly<Store>` consumes the existing cmmr Store port, supplied through cvtl;
there is no parallel persistence implementation. Requests bind opaque room and
operation IDs. Resume creates a fresh random transport ordering generation; the production pass adapter starts its local counter at zero. This is not an MLS epoch or a recovered member counter. CAS
serializes changes; same-operation replay returns the recorded outcome and a
changed request under the same operation is refused. Every record expires.
Connection handles are anonymous room-local random values, never attendance,
member, device or transport identity. Losing the last connection forgets state.

`Permit` has no public constructor or deserializer. `passes::Verifier` verifies the real RFC9474 room-scoped pass plus possession of its anonymous Ed25519 connection key over the exact request and current server incarnation. No membership verdict or caller counter is accepted. `UnavailableProofs` remains a refusing fallback. The previous AllocationLedger issuer is not reused. `handover` remains unavailable until the actual member-side fork winner reaches the listing facade; Assembly does not decide size from client claims.
Internal tests supply prevalidated capability preconditions to exercise real
Memory CAS, byte retention, expiry, restart and bounds. They are NOT evidence
of anonymous permit correctness, counter-recovery proof or real-Tor delivery.

Open: authenticated issuance routing and quota enforcement, actual member MLS reconciliation across transport generations and member-side listing transfer; reader acknowledgements/relay fan-out through Link, production Valkey composition and LT-ROOMS. No full room acceptance claimed.

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


The required native check also runs `valkey-conformance` against a disposable,
persistence-disabled Valkey service. The same real-memory/Valkey vector checks
nonadjacent replay, altered-body refusal and expiry despite interleaved relay.
Missing service availability fails the check. Its internal permit preconditions
are not a production anonymous proof or end-to-end room test.


## Admission-only pass candidate

`passes::Epoch` is one common authenticated descriptor per community/epoch with
a dedicated RSA-3072 public key. Never accept a peer-selected/personalized issuer
key. It uses the existing maintained RFC9474 SHA384/PSS/randomized suite. A client
`PreparedPass` blinds the context, room and fresh anonymous connection public key.
`BlindRequest` contains only common context plus blinded bytes. Native
`passes::issuer::Issuer` uses OpenSSL for the private RSA operation with a fault
check; it has no allocation database or accounting debit. The cfrm facade must
perform actual authenticated admission, reviewed issuance quota and cthl first.
One-per-hidden-room quota is not falsely claimed by this primitive.

`ClientPass::prove` signs the exact room request and server incarnation with the
pass-bound anonymous connection key. Foreign room, connection, request, epoch,
expiry, signature and incarnation fail. Relay/read/order also require that actual
connection to be active in the room. No member/device identity is retained.
Client blinding and signing state are private, nonserializable session objects;
Link cancellation or loss of this state does not authorize replacement issuance.

`Outcome.ordering` identifies the current random transport generation. A reset
always changes it, even if a previous Resume is presented in the same pass epoch.
Members must reconcile authentic MLS state before treating any new-generation
transport order as a group transition. Assembly's volatile request receipts only
provide same-generation idempotence; they cannot detect all replay after state
loss. Actual MLS replay protection remains mandatory.

Native OpenSSL and portable native/browser blind-RSA round trips are written,
including scope/tamper/refusal and actual Memory ordering tests. They have not
executed. The strict coverage gate includes every production source with native
issuer enabled; no exclusions or threshold reductions were added.
