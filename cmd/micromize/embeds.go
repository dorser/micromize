//go:build release

package main

import (
	_ "embed"
)

//go:embed build/fs-restrict.tar
var fsRestrictGadgetBytes []byte

//go:embed build/cap-restrict.tar
var capRestrictGadgetBytes []byte

//go:embed build/ptrace-restrict.tar
var ptraceRestrictGadgetBytes []byte
