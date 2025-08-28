package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run . <api-key-to-hash>")
	}
	key := os.Args[1]
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hashedKeyBytes := hasher.Sum(nil)
	hashedKeyStr := hex.EncodeToString(hashedKeyBytes)

	fmt.Println(hashedKeyStr)
}
