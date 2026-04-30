#!/usr/bin/env bash
# Test: AF_ALG hash (non-AEAD) restriction inside container
# Verify that the generic AF_ALG policy blocks non-AEAD types too.

test_af_alg_hash_restrict() {
  begin_test "AF_ALG hash socket blocked inside container"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the AF_ALG hash probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/af-alg-hash-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/af_alg_hash); then
    fail_test "failed to build AF_ALG hash probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-af-alg-hash"
  local cid="micromize-test-af-alg-hash"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/af-alg-hash-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "AF_ALG hash probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  if echo "$output" | grep -qF "blocked: AF_ALG"; then
    pass_test
  else
    fail_test "Expected AF_ALG hash to be blocked, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_af_alg_hash_restrict
