package main

// Version is the version of the gadgets to run.
// It is set at build time via -ldflags.
var Version = "latest"

func main() {
	Execute()
}
