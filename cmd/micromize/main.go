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

// Version is the version of the gadgets to run.
// It is set at build time via -ldflags.
var Version = "latest"

func main() {
	Execute()
}
