package dangerous

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"hash"
	"io"
)

func base64Encode(data []byte) []byte {
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

func bytesToInt64(b []byte) int64 {
	var n int64
	for _, x := range b {
		n = (n << 8) | int64(x)
	}
	return n
}

func int64ToBytes(i int64) []byte {
	var o []byte
	for i > 0 {
		o = append([]byte{byte(i & 0b11111111)}, o...)
		i = i >> 8
	}
	return o
}

func zlibCompress(data []byte) ([]byte, error) {
	b := new(bytes.Buffer)
	w := zlib.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	_ = w.Close()
	return b.Bytes(), nil
}

func zlibDecompress(compressedData []byte) ([]byte, error) {
	b := bytes.NewBuffer(compressedData)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var o []byte
	for {
		x := make([]byte, 512)
		n, err := r.Read(x)
		o = append(o, x...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if n < 512 {
			break
		}
	}

	o = bytes.TrimRight(o, "\x00") // Because we read in 512 byte blocks, we
	// can end up with loads of blank data that breaks unmarshaling

	return o, nil
}