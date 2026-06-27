// Copyright The micromize authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	afKey   = 15 // AF_KEY / PF_KEY
	pfKeyV2 = 2  // PF_KEY_V2 protocol
)

// AF_KEY (PF_KEY) is one of the two ways to program host IPsec/XFRM state and is
// part of the DirtyClone (CVE-2026-43503) killchain. socket-restrict must deny
// its creation inside containers. The LSM socket_create hook runs before the
// protocol family handler, so enforcement yields EPERM even on kernels that
// would otherwise return EAFNOSUPPORT.
func main() {
	fd, err := syscall.Socket(afKey, syscall.SOCK_RAW, pfKeyV2)
	if err != nil {
		if err == syscall.EPERM || err == syscall.EACCES {
			fmt.Printf("blocked: AF_KEY socket creation denied: %v\n", err)
			return
		}
		fmt.Printf("socket-error: %v\n", err)
		os.Exit(2)
	}
	defer syscall.Close(fd) //nolint:errcheck

	fmt.Println("not-blocked: AF_KEY socket creation succeeded")
	os.Exit(42)
}
