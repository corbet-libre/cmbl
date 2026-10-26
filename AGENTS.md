# cmbl agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run from the lane root (`<lane>/ws`); `cbuild <lane> ...` builds there.

Build and test (quote the verdict line, never infer from a pipe):
- `cbuild <lane> fmt -p cmbl -- --check` — must be clean
- `cbuild <lane> test -p cmbl --locked` — lib `11`, `admission_passes` `1`,
  `settlement_tokens` `2`, doc `0` passed, exit 0; long, background it
- `cbuild <lane> test -p cmbl --locked --features issuer` — lib `11`,
  `admission_passes` `2`, `quota_issuer` `2`, `settlement_tokens` `4`,
  doc `0` passed, exit 0 (native OpenSSL suite; needs OpenSSL dev libs)
- `cbuild <lane> clippy -p cmbl --locked --all-targets -- -D warnings` — exit 0
- `cbuild <lane> check -p cmbl --locked --target wasm32-unknown-unknown` — exit 0
- Full gate (first-party refresh, Valkey parity, wasm vectors with a real
  browser runner, coverage) runs in CI; see `.ci/verify.sh`, `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Blind pass binds room, connection, request and epoch; a resume always
  changes the transport generation; foreign or malformed passes refused
  -> `tests/admission_passes.rs::actual_blind_pass_binds_room_connection_request_epoch_and_restart`
- A join is answered only while live, a bounded number of times; replay
  returns the recorded outcome, a changed request is refused, records expire
  -> `tests/internal/mod.rs::a_join_request_is_answered_only_while_live_and_a_bounded_number_of_times`,
  `::real_memory_order_replay_expiry_and_restart`
- Scope and freshness fail before storage; limits checked before opening;
  corruption and impossible deadlines refused
  -> `::scope_and_freshness_fail_before_storage`, `::limits_are_checked_before_opening`,
  `::real_storage_refuses_corruption_and_impossible_deadline`
- Settlement tokens bind deposit, epoch, request and exclusive time; room
  and outcome transcripts use dedicated keys that refuse cross-use
  -> `tests/settlement_tokens.rs::real_token_binds_deposit_epoch_request_and_exclusive_time`,
  `::room_and_outcome_transcripts_are_distinct_and_dedicated_keys_refuse_cross_use`
- Provisioned-key restore matches the original anchor; old tokens need no
  private key; concurrent issuance cannot spend one allowance twice
  -> `::provisioned_key_restore_matches_original_anchor_and_old_tokens_need_no_private_key`,
  `tests/quota_issuer.rs::concurrent_real_issuance_cannot_spend_one_allowance_twice`

Pointers: `src/passes.rs`, `src/settlement.rs`, `src/listing.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only deps.
