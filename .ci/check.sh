#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS=2 CARGO_NET_GIT_FETCH_WITH_CLI=true
trap 'sha256sum Cargo.lock' EXIT
rustc -Vv
sha256sum Cargo.lock
python3 .github/check-first-party.py --archive
case "${1:?check required}" in
  resolve)
    : "${CARGO_TARGET_DIR:?}" "${CI_COMMIT_SHA:?}"
    cargo update
    cargo metadata --locked --format-version 1 > dependency-metadata.json
    artifacts="$CARGO_TARGET_DIR/qualification/$CI_COMMIT_SHA"
    mkdir -p "$artifacts"
    cp Cargo.lock dependency-metadata.json "$artifacts/"
    rustc -Vv > "$artifacts/compiler.txt"
    date --utc --iso-8601=seconds > "$artifacts/resolved-at.txt"
    sha256sum Cargo.lock
    ;;
  native)
    cargo fmt --all --check
    cargo clippy --locked --all-targets --features issuer -- -D warnings
    cargo test --locked --features issuer
    ;;
  browser)
    command -v wasm-bindgen-test-runner >/dev/null
    export CHROMEDRIVER="$(command -v chromedriver)"
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export WASM_BINDGEN_USE_BROWSER=1 WASM_BINDGEN_TEST_TIMEOUT=180
    cargo test --locked --target wasm32-unknown-unknown --tests
    ;;
  coverage)
    command -v cargo-llvm-cov >/dev/null
    case "$(rustc --version)" in *nightly*) ;; *) echo "Branch coverage requires the provisioned nightly toolchain" >&2; exit 1 ;; esac
    cargo llvm-cov --locked --features issuer --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
    python3 .github/check-coverage.py coverage.json
    ;;
  dependency-policy)
    cargo deny --locked check advisories
    ;;
  valkey)
    : "${VALKEY_URL:?actual persistence-disabled Valkey required}"
    cargo clippy --locked --all-targets --features issuer,valkey-conformance -- -D warnings
    cargo test --locked --features issuer,valkey-conformance tests::valkey::real_memory_and_valkey_replay_expiry_parity -- --exact --nocapture
    ;;
  *) exit 2 ;;
esac
