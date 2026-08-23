#!/usr/bin/env bash

set -euo pipefail

if [[ "${1:-}" == "--runner" ]]; then
  : "${PROOF_CGROUP_ROOT:?}" "${PROOF_USER:?}" "${PROOF_HOME:?}" "${PROOF_TARGET:?}"
  : "${PROOF_SANDBOX:?}" "${PROOF_CARGO:?}" "${PROOF_MANIFEST:?}"
  proof_cargo_target=()
  if [[ -n "${PROOF_RUST_TARGET:-}" ]]; then
    proof_cargo_target=(--target "$PROOF_RUST_TARGET")
  fi
  printf '%s\n' "$$" > "$PROOF_CGROUP_ROOT/runner/cgroup.procs"
  runuser -u "$PROOF_USER" -- env \
    HOME="$PROOF_HOME" \
    PATH="$PROOF_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    CARGO_TARGET_DIR="$PROOF_TARGET" \
    TOKENSAVER_PLUGIN_SANDBOX_ROOT="$PROOF_SANDBOX" \
    TOKENSAVER_PLUGIN_CGROUP_PARENT="$PROOF_CGROUP_ROOT/sandboxes" \
    "$PROOF_CARGO" test --locked \
      "${proof_cargo_target[@]}" \
      --manifest-path "$PROOF_MANIFEST" \
      -p tokensaver-plugin-runtime-host \
      --test native_runtime -- --ignored --nocapture

  if [[ -n "${PROOF_GO_TEST:-}" ]]; then
    runuser -u "$PROOF_USER" -- env \
      HOME="$PROOF_HOME" \
      PATH="/usr/local/bin:/usr/bin:/bin" \
      TOKENSAVER_NATIVE_PLUGIN_E2E_HOST="$PROOF_TARGET/debug/tokensaver-plugin-runtime-host" \
      TOKENSAVER_NATIVE_PLUGIN_E2E_SANDBOX="$PROOF_SANDBOX" \
      TOKENSAVER_NATIVE_PLUGIN_E2E_CGROUP="$PROOF_CGROUP_ROOT/sandboxes" \
      "$PROOF_GO_TEST" -test.run='^TestNativeProductEndToEnd$' -test.v
  fi
  exit 0
fi

die() {
  printf '[runtime-host WSL proof] %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "run as root so the proof can delegate a cgroup v2 subtree"
[[ $# -eq 1 || $# -eq 2 ]] || die "usage: test-runtime-host-wsl.sh UNIX_USER [LINUX_GO_TEST_BINARY]"
test_user="$1"
go_test_source="${2:-}"
if [[ -n "$go_test_source" ]]; then
  [[ -f "$go_test_source" && ! -L "$go_test_source" ]] || die "Linux Go test binary is unavailable or unsafe"
fi
[[ "$test_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid UNIX user"
test_home="$(getent passwd "$test_user" | cut -d: -f6)"
[[ -n "$test_home" && -d "$test_home" ]] || die "test user home is unavailable"
test_group="$(id -gn "$test_user")"
[[ -n "$test_group" ]] || die "test user group is unavailable"
cargo_bin="$test_home/.cargo/bin/cargo"
[[ -x "$cargo_bin" ]] || die "test user Cargo executable is unavailable"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
sdk_root="$(cd -- "$script_dir/.." && pwd -P)"
manifest="$sdk_root/Cargo.toml"
[[ -f "$manifest" ]] || die "SDK Cargo manifest is unavailable"
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || die "cgroup v2 is unavailable"
grep -qw memory /sys/fs/cgroup/cgroup.controllers || die "cgroup memory controller is unavailable"
grep -qw pids /sys/fs/cgroup/cgroup.controllers || die "cgroup pids controller is unavailable"

proof_root="/sys/fs/cgroup/tokensaver-plugin-proof-$$"
proof_target="$(mktemp -d /tmp/tokensaver-plugin-proof-target.XXXXXX)"
proof_sandbox="$(mktemp -d /tmp/tokensaver-plugin-proof-sandbox.XXXXXX)"
proof_go_test=""
if [[ -n "$go_test_source" ]]; then
  proof_go_test="$proof_target/pluginplatform-e2e.test"
fi

cleanup() {
  local result=$?
  trap - EXIT HUP INT TERM
  case "$proof_target" in /tmp/tokensaver-plugin-proof-target.*) rm -rf -- "$proof_target" ;; esac
  case "$proof_sandbox" in /tmp/tokensaver-plugin-proof-sandbox.*) rm -rf -- "$proof_sandbox" ;; esac
  case "$proof_root" in
    /sys/fs/cgroup/tokensaver-plugin-proof-[0-9]*)
      rmdir "$proof_root/runner" "$proof_root/sandboxes" "$proof_root" 2>/dev/null || true
      ;;
  esac
  exit "$result"
}
trap cleanup EXIT HUP INT TERM

if [[ -n "$proof_go_test" ]]; then
  cp -- "$go_test_source" "$proof_go_test"
  chmod 0755 "$proof_go_test"
fi

mkdir "$proof_root"
mkdir "$proof_root/runner" "$proof_root/sandboxes"
printf '%s\n' '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
printf '%s\n' '+memory +pids' > "$proof_root/cgroup.subtree_control"
printf '%s\n' '+memory +pids' > "$proof_root/sandboxes/cgroup.subtree_control"
chown -R "$test_user:$test_group" "$proof_root" "$proof_target" "$proof_sandbox"
chmod 0700 "$proof_target" "$proof_sandbox"

PROOF_CGROUP_ROOT="$proof_root" \
PROOF_USER="$test_user" \
PROOF_HOME="$test_home" \
PROOF_TARGET="$proof_target" \
PROOF_SANDBOX="$proof_sandbox" \
PROOF_CARGO="$cargo_bin" \
PROOF_MANIFEST="$manifest" \
PROOF_GO_TEST="$proof_go_test" \
PROOF_RUST_TARGET="${PROOF_RUST_TARGET:-}" \
  bash "$script_dir/test-runtime-host-wsl.sh" --runner

printf '[runtime-host WSL proof] native confinement passed\n'
