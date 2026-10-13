#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
: "${CARGO_TARGET_DIR:?}" "${CI_COMMIT_SHA:?}"
export PYTHONDONTWRITEBYTECODE=1
artifacts="${CI_ACCEPTANCE_ARTIFACTS:-$CARGO_TARGET_DIR/qualification/$CI_COMMIT_SHA/${1:?check required}}"
mkdir -p "$artifacts"
export CARGO_BUILD_JOBS=2 CARGO_NET_GIT_FETCH_WITH_CLI=true
trap 'sha256sum Cargo.lock | tee "$artifacts/lock-after.sha256"' EXIT
rustc -Vv | tee "$artifacts/compiler.txt"
sha256sum Cargo.lock | tee "$artifacts/lock-before.sha256"
python3 .github/check-first-party.py --archive
case "${1:?check required}" in
  resolve)
    : "${CARGO_TARGET_DIR:?}" "${CI_COMMIT_SHA:?}"
    cargo update
    cargo metadata --locked --format-version 1 > "$artifacts/dependency-metadata.json"
    cp Cargo.lock "$artifacts/Cargo.lock"
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
  wasm)
    cargo clippy --locked --target wasm32-unknown-unknown --all-targets -- -D warnings
    ;;
  coverage)
    (
      printf '%s  %s\n' '212a02eaa479a023b9ef94d8907269de2c6f1c8dce6337f4f6904b8f97ba6f96' '/nix/store/a7wahr975zknixs667f1vl68r4jpm5kx-cmty-coverage-tools/share/cmty-coverage-tools/setup.sh' | sha256sum --check --strict
      . '/nix/store/a7wahr975zknixs667f1vl68r4jpm5kx-cmty-coverage-tools/share/cmty-coverage-tools/setup.sh'
      rustc -Vv | tee "$artifacts/compiler.txt"
      command -v cargo-llvm-cov >/dev/null
      case "$(rustc --version)" in *nightly*) ;; *) echo "Branch coverage requires the provisioned nightly toolchain" >&2; exit 1 ;; esac
      cargo llvm-cov --locked --features issuer --branch --json --output-path "$artifacts/coverage.json" --ignore-filename-regex '/tests/'
      cargo llvm-cov report --branch --lcov --output-path "$artifacts/coverage.lcov" --ignore-filename-regex '/tests/'
      cargo llvm-cov report --branch --text --output-path "$artifacts/coverage.txt" --ignore-filename-regex '/tests/'
      python3 .github/check-coverage.py "$artifacts/coverage.json"
    )
    ;;
  dependency-policy)
    cargo deny --locked check advisories
    ;;
  valkey)
    : "${VALKEY_URL:?actual persistence-disabled Valkey required}"
    cargo clippy --locked --all-targets --features issuer,valkey-conformance -- -D warnings
    cargo test --locked --features issuer,valkey-conformance tests::valkey::real_memory_and_valkey_replay_expiry_parity -- --exact --nocapture | tee "$artifacts/valkey.log"
    rg -q '1 passed; 0 failed' "$artifacts/valkey.log"
    ;;
  *) exit 2 ;;
esac
