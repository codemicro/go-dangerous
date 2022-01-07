package dangerous

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateKey() ([]byte, error) {
	c := 16

	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	asHex := make([]byte, c*2)
	hex.Encode(asHex, b)
	
	return asHex, nil
}
