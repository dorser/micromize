#!/usr/bin/env bash
# Test: AF_KEY (PF_KEY IPsec) restriction inside container
# Verify the DirtyClone (CVE-2026-43503) XFRM/IPsec config primitive is blocked
# before any vulnerable kernel XFRM path can be reached.

test_af_key_restrict() {
  begin_test "AF_KEY socket blocked inside container"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the AF_KEY probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/af-key-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/af_key); then
    fail_test "failed to build AF_KEY probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-af-key"
  local cid="micromize-test-af-key"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/af-key-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "AF_KEY probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  if echo "$output" | grep -qF "blocked: AF_KEY"; then
    pass_test
  else
    fail_test "Expected AF_KEY socket creation to be blocked, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_af_key_restrict
