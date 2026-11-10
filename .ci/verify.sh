#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
: "${CI_COMMIT_SHA:?verify requires the exact source revision}"
: "${ARTIFACT_ROOT:?verify requires an absolute ARTIFACT_ROOT}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 .github/check-first-party.py
rustc --version
# fmt patch gate (hosted: fmt; diff > patch; fail on non-empty)
cargo fmt --all
git diff -- '*.rs' > "$ARTIFACT_ROOT/formatting.patch"
test ! -s "$ARTIFACT_ROOT/formatting.patch"
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
# shellcheck disable=SC1091
. "$PWD/.ci/bin/valkey-helpers.sh"

# Disposable Valkey fixture (reviewed cvlk lifecycle): one owned server, unique
# loopback port, exact PID/start-tick/argv identity, detached stdio, BOTH job
# lock fds 8/9 closed in the server child, readiness on the owned PID only,
# cleanup kills the owned process only (never a sibling job's fixture).
# Hosted used a docker service + `docker exec CONFIG SET`; the nix server gets
# the same three settings explicitly below, then the same VALKEY_URL parity gate.
start_valkey() {
  VALKEY_TMP="$(mktemp -d)"
  export VALKEY_TMP
  VALKEY_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
  export VALKEY_PORT
  printf 'port %s\nbind 127.0.0.1\nprotected-mode yes\ndir %s\ndbfilename dump.rdb\n' "$VALKEY_PORT" "$VALKEY_TMP" > "$VALKEY_TMP/valkey.conf"
  export VALKEY_CONF="$VALKEY_TMP/valkey.conf"
  export VALKEY_PIDFILE="$VALKEY_TMP/valkey.pid"
  export VALKEY_STARTTICKFILE="$VALKEY_TMP/valkey.starttick"
  valkey-server "$VALKEY_CONF" --daemonize no --logfile "$VALKEY_TMP/valkey.log" \
    0</dev/null >>"$VALKEY_TMP/valkey.log" 2>&1 8>&- 9>&- &
  echo "$!" > "$VALKEY_PIDFILE"
  record_server_identity "$!" "$VALKEY_STARTTICKFILE"
  # Readiness: the port is ephemeral, so a ping alone proves nothing — recheck
  # the recorded PID/start-tick identity on EVERY step, and gate once more
  # after success, before any ping-trusting CONFIG. Otherwise a recycled port
  # could let us reconfigure a sibling job's fixture.
  assert_owned_ready() {
    _aor_pid="$(cat "$VALKEY_PIDFILE")"
    _aor_tick="$(cat "$VALKEY_STARTTICKFILE")"
    is_owned_server "$_aor_pid" "$_aor_tick" || return 1
    proc_alive "$_aor_pid" || return 1
  }
  for _ in $(seq 1 50); do
    assert_owned_ready || { echo "cmbl fixture: owned server lost during readiness" >&2; return 1; }
    if valkey-cli -p "$VALKEY_PORT" ping >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
  assert_owned_ready || { echo "cmbl fixture: refusing ping from unowned server" >&2; return 1; }
  valkey-cli -p "$VALKEY_PORT" ping
  valkey-cli -p "$VALKEY_PORT" CONFIG SET save ""
  valkey-cli -p "$VALKEY_PORT" CONFIG SET appendonly no
  valkey-cli -p "$VALKEY_PORT" CONFIG SET maxmemory-policy noeviction
  export VALKEY_URL="redis://127.0.0.1:${VALKEY_PORT}/"
}
stop_valkey() {
  if [ -n "${VALKEY_PIDFILE:-}" ] && [ -f "$VALKEY_PIDFILE" ] \
    && [ -n "${VALKEY_STARTTICKFILE:-}" ] && [ -f "$VALKEY_STARTTICKFILE" ]; then
    pid="$(cat "$VALKEY_PIDFILE")"
    expected_tick="$(cat "$VALKEY_STARTTICKFILE")"
    # Only signal the owned server (PID + start tick); then confirm exit
    # BEFORE deleting the data dir, so no live server ever loses its files.
    if is_owned_server "$pid" "$expected_tick"; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do
        proc_alive "$pid" || break
        sleep 0.1
      done
      if proc_alive "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
        sleep 0.5
      fi
      if proc_alive "$pid"; then
        echo "cmbl fixture: owned server PID $pid did not exit; keeping $VALKEY_TMP" >&2
        return 1
      fi
    fi
  fi
  if [ -n "${VALKEY_TMP:-}" ] && [ -d "$VALKEY_TMP" ]; then
    rm -rf "$VALKEY_TMP"
  fi
  unset VALKEY_PIDFILE VALKEY_STARTTICKFILE VALKEY_CONF VALKEY_PORT VALKEY_TMP VALKEY_URL || true
}
cleanup_valkey() { stop_valkey; }
trap cleanup_valkey EXIT
start_valkey
cargo clippy --locked --all-targets --features valkey-conformance -- -D warnings
VALKEY_URL="$VALKEY_URL" cargo test --locked --features valkey-conformance tests::valkey::real_memory_and_valkey_replay_expiry_parity -- --exact --nocapture | tee "$ARTIFACT_ROOT/real-valkey.log"
grep -q '1 passed; 0 failed' "$ARTIFACT_ROOT/real-valkey.log"
stop_valkey
trap - EXIT
cargo metadata --locked --format-version 1 > dependency-metadata.json
version=$(jq -r '.packages[] | select(.name == "wasm-bindgen") | .version' dependency-metadata.json)
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="${WASM_BINDGEN_DOWNLOAD_BASE:-https://github.com/wasm-bindgen/wasm-bindgen/releases/download}/${version}"
mkdir -p "$RUNNER_TEMP/wasm-runner"
(cd "$RUNNER_TEMP/wasm-runner" && curl --fail --location --retry 3 --remote-name "$base/$archive" && curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum" && checksum=$(cut -d ' ' -f1 "$archive.sha256sum") && printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check && tar -xzf "$archive" --strip-components=1)
export PATH="$RUNNER_TEMP/wasm-runner:$PATH"
# The runner supplies pinned nix chromium and chromedriver; link the browser
# under the name the stock discovery expects, job-locally.
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
python3 - <<'PYTHON'
import json, os
with open('webdriver.json', 'w') as output:
    json.dump({'goog:chromeOptions': {'binary': os.environ['CHROME_BIN']}}, output)
PYTHON
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test --locked --target wasm32-unknown-unknown --tests
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
python3 .github/check-coverage.py coverage.json
