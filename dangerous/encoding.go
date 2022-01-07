package dangerous

import (
	"crypto/hmac"
	"encoding/base64"
	"hash"
)

func encodeBase64(data []byte) []byte {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(encoded, data)
	return encoded
}

func decodeBase64(encodedData []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encodedData)))
	if _, err := base64.RawURLEncoding.Decode(decoded, encodedData); err != nil {
		return nil, err
	}
	return decoded, nil
}

type HashConstructor func() hash.Hash

func hashData(data []byte, hc HashConstructor) []byte {
	h := hc()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func generateHMACHash(data, key []byte, hc HashConstructor) []byte {
	return hashData(data, func() hash.Hash {
		return hmac.New(hc, key)
	})
}