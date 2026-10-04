package main

import (
	"fmt"
	"os"

	"vpnstack/internal/singbox"
)

func main() {
	keys := singbox.RealityKeys()
	if len(keys) == 0 {
		os.Exit(0)
	}
	for _, key := range keys {
		fmt.Printf("%s=%s\n", key.Tag, key.PublicKey)
	}
}
