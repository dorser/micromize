#!/usr/bin/env bash
# Test: NETLINK_XFRM restriction inside container
# Verify the DirtyClone (CVE-2026-43503) XFRM/IPsec config primitive is blocked
# before any vulnerable kernel XFRM path can be reached.

test_xfrm_netlink_restrict() {
  begin_test "NETLINK_XFRM socket blocked inside container"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the NETLINK_XFRM probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/xfrm-netlink-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/xfrm_netlink); then
    fail_test "failed to build NETLINK_XFRM probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-xfrm-netlink"
  local cid="micromize-test-xfrm-netlink"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/xfrm-netlink-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "NETLINK_XFRM probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  if echo "$output" | grep -qF "blocked: NETLINK_XFRM"; then
    pass_test
  else
    fail_test "Expected NETLINK_XFRM socket creation to be blocked, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_xfrm_netlink_restrict
