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
	"unsafe"
)

const (
	afALG         = 38
	sockSeqpacket = 5
)

type sockaddrALG struct {
	Family uint16
	Type   [14]byte
	Feat   uint32
	Mask   uint32
	Name   [64]byte
}

func main() {
	fd, err := syscall.Socket(afALG, sockSeqpacket, 0)
	if err != nil {
		if err == syscall.EPERM || err == syscall.EACCES {
			fmt.Printf("blocked: AF_ALG socket creation denied: %v\n", err)
			return
		}
		fmt.Printf("socket-error: %v\n", err)
		os.Exit(2)
	}
	defer syscall.Close(fd) //nolint:errcheck

	addr := sockaddrALG{Family: afALG}
	copy(addr.Type[:], "aead")
	copy(addr.Name[:], "authencesn(hmac(sha256),cbc(aes))")

	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr)) //nolint:gosec // Required for AF_ALG sockaddr
	if errno == 0 {
		fmt.Println("not-blocked: AF_ALG AEAD bind succeeded")
		os.Exit(42)
	}

	if errno == syscall.EPERM || errno == syscall.EACCES {
		fmt.Printf("blocked: AF_ALG AEAD bind denied: %v\n", errno)
		return
	}

	fmt.Printf("bind-error: %v\n", errno)
	os.Exit(2)
}
