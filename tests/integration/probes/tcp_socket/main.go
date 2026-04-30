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

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("blocked: TCP socket creation failed: %v\n", err)
		os.Exit(1)
	}
	syscall.Close(fd) //nolint:errcheck,gosec

	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Printf("blocked: UDP socket creation failed: %v\n", err)
		os.Exit(1)
	}
	syscall.Close(fd) //nolint:errcheck,gosec

	fmt.Println("ok: TCP and UDP sockets work normally")
}
