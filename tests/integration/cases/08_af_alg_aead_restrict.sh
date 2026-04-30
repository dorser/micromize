#!/usr/bin/env bash
# Test: AF_ALG AEAD restriction inside container
# Verify that the CVE-2026-31431 killchain is blocked before algif_aead is reached.

test_af_alg_aead_restrict() {
  begin_test "AF_ALG AEAD socket blocked inside container"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the AF_ALG probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/af-alg-aead-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/af_alg_aead); then
    fail_test "failed to build AF_ALG probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-af-alg"
  local cid="micromize-test-af-alg"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/af-alg-aead-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "AF_ALG probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  if echo "$output" | grep -qF "blocked: AF_ALG"; then
    pass_test
  else
    fail_test "Expected AF_ALG AEAD bind to be blocked, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_af_alg_aead_restrict
