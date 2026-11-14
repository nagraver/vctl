package main

import (
	"fmt"
	"github.com/nagraver/vctl/internal/whale"
	"os"
)

func main() {
	if err := whale.ExecuteBackend(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
