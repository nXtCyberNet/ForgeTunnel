package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Printf("SERVER_PRIVATE_KEY_HEX=%s\n", hex.EncodeToString(priv))
	fmt.Printf("SERVER_PUBLIC_KEY_HEX=%s\n", hex.EncodeToString(pub))
}
