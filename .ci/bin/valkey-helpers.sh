#!/usr/bin/env bash
# Owned-server identity helpers for the disposable Valkey fixture.
# No side effects when sourced. Linux-only (/proc).
# A PID is treated as the owned server only when BOTH hold:
#   - /proc/<pid> argv[0] basename is exactly valkey-server, and
#   - /proc/<pid> start tick equals the recorded tick.
# argv[0] basename (not substring): a parent shell's -c string may mention
# valkey-server textually. Start ticks reject PID reuse.
proc_starttick() {
  # Start time is field 22 overall; the comm field may contain spaces, so
  # parse after the final ')' exactly like proc_state, then take field 20.
  _cst_stat="$(cat "/proc/$1/stat" 2>/dev/null || true)"
  [ -n "$_cst_stat" ] || return 1
  _cst_stat="${_cst_stat##*)}"
  _cst_stat="${_cst_stat# }"
  set -- $_cst_stat
  case "${20}" in '' | *[!0-9]*) return 1 ;; *) printf '%s' "${20}" ;; esac
}
proc_argv0_base() {
  _cvb_cmdline="$({ tr '\0' ' ' < "/proc/$1/cmdline"; } 2>/dev/null || true)"
  [ -n "$_cvb_cmdline" ] || return 1
  basename "${_cvb_cmdline%% *}"
}
is_owned_server() {
  [ -n "${1:-}" ] || return 1
  case "$1" in '' | *[!0-9]* | 0) return 1 ;; esac
  [ -n "${2:-}" ] || return 1
  case "$2" in '' | *[!0-9]*) return 1 ;; esac
  [ "$(proc_argv0_base "$1")" = "valkey-server" ] || return 1
  [ "$(proc_starttick "$1")" = "$2" ] || return 1
}
# State comes from field 3 of /proc/<pid>/stat (parsed after the last ')'
# so comm spaces are harmless).
proc_state() {
  _cps_stat="$(cat "/proc/$1/stat" 2>/dev/null || true)"
  [ -n "$_cps_stat" ] || return 1
  _cps_stat="${_cps_stat##*)}"
  _cps_stat="${_cps_stat# }"
  printf '%s' "${_cps_stat%% *}"
}
# Liveness treats only dead states as exited: zombies (Z), dead (X/x).
# Stopped (T/t), idle (I), and parking (W/P) processes are LIVE — a stopped
# owned server still owns its data dir, which must never be deleted under it.
# Nonexistent PIDs are not live. (kill -0 alone cannot distinguish zombies,
# which it still answers; a killed server child whose parent has not reaped
# it yet must count as exited.)
proc_alive() {
  case "$(proc_state "$1")" in '' | Z | X | x) return 1 ;; *) return 0 ;; esac
}
record_server_identity() {
  # $1 = pid, $2 = tick-file path. Retries until the tick is observable.
  for _ in $(seq 1 50); do
    _cvb_tick="$(proc_starttick "$1")"
    case "$_cvb_tick" in '' | *[!0-9]*) sleep 0.1 ;; *)
      printf '%s\n' "$_cvb_tick" > "$2"
      return 0
      ;;
    esac
  done
  echo "valkey helpers: start tick never observable for PID $1" >&2
  return 1
}
