#!/usr/bin/env bash
# Test: Normal TCP/UDP sockets still work inside container
# Verify the AF_ALG policy does not block ordinary networking.

test_normal_sockets() {
  begin_test "TCP and UDP sockets still work inside container"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the TCP socket probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/tcp-socket-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/tcp_socket); then
    fail_test "failed to build TCP socket probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-tcp-socket"
  local cid="micromize-test-tcp-socket"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/tcp-socket-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "TCP socket probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  if echo "$output" | grep -qF "ok: TCP and UDP sockets work normally"; then
    pass_test
  else
    fail_test "Expected normal sockets to work, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_normal_sockets
