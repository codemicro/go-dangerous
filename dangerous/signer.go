package dangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
)

type SignerOption func(s *Signer)
type KeyDerivationMode uint8

const (
	KeyDerivationModeConcat       KeyDerivationMode = iota
	KeyDerivationModeDjangoConcat KeyDerivationMode = iota
)

type Signer struct {
	Keys              [][]byte
	Separator         byte
	DigestHash        HashConstructor
	Salt              []byte
	KeyDerivationMode KeyDerivationMode
}

var (
	ErrInvalidKeyLength = errors.New("dangerous: invalid key length, must be 32 bytes")
	ErrNoKeys           = errors.New("dangerous: no available signing keys")
	ErrInvalidFormat    = errors.New("dangerous: invalid signature format")
	ErrInvalidSignature = errors.New("dangerous: signature does not match data")
)

func NewSigner(opts ...SignerOption) (*Signer, error) {

	s := &Signer{
		Separator:         '.',
		DigestHash:        sha1.New,
		Salt:              []byte("itsdangerous.Signer"),
		KeyDerivationMode: KeyDerivationModeDjangoConcat,
	}

	for _, optionFunction := range opts {
		optionFunction(s)
	}

	if len(s.Keys) == 0 {
		return nil, ErrNoKeys
	} else {
		for _, key := range s.Keys {
			if len(key) != 32 {
				return nil, ErrInvalidKeyLength
			}
		}
	}

	return s, nil
}

func WithDigest(d HashConstructor) SignerOption {
	return func(s *Signer) {
		s.DigestHash = d
	}
}

func WithKey(k []byte) SignerOption {
	return func(s *Signer) {
		s.Keys = [][]byte{k}
	}
}

func WithKeys(ks [][]byte) SignerOption {
	return func(s *Signer) {
		s.Keys = ks
	}
}

func (s *Signer) getBaseKey() ([]byte, error) {
	if len(s.Keys) == 0 {
		return nil, ErrNoKeys
	}

	return s.Keys[len(s.Keys)-1], nil
}

func (s *Signer) deriveSigningKey(signingKey []byte) []byte {
	// TODO: more derivation modes

	if s.KeyDerivationMode == KeyDerivationModeConcat {
		signingKey = hashData(
			append(s.Salt, signingKey...),
			s.DigestHash,
		)
	} else if s.KeyDerivationMode == KeyDerivationModeDjangoConcat {
		signingKey = hashData(
			append(append(s.Salt, []byte("signer")...), signingKey...),
			s.DigestHash,
		)
	} else {
		panic("dangerous: unknown key derivation mode")
	}

	return signingKey
}

func (s *Signer) getNewSignature(data []byte) ([]byte, error) {
	baseKey, err := s.getBaseKey()
	if err != nil {
		return nil, err
	}
	signingKey := s.deriveSigningKey(baseKey)

	base64HMACValue := encodeBase64(
		generateHMACHash(data, signingKey, s.DigestHash),
	)

	return base64HMACValue, nil
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	if signature, err := s.getNewSignature(data); err != nil {
		return nil, err
	} else {
		return append(append(data, s.Separator), signature...), nil
	}
}

// validateSignature checks value against signatures creates by all keys known to *Signer s.
// `signature` should be base64 encoded.
func (s *Signer) validateSignature(value, signature []byte) bool {
	decodedSignature, err := decodeBase64(signature)
	if err != nil {
		return false
	}

	for _, key := range s.Keys {
		if hmac.Equal(
			decodedSignature,
			generateHMACHash(value, s.deriveSigningKey(key), s.DigestHash),
		) {
			return true
		}
	}

	return false
}

func (s *Signer) Unsign(signedValue []byte) ([]byte, error) {
	rightmostSep := bytesRIndex(signedValue, s.Separator)
	if rightmostSep == -1 {
		return nil, ErrInvalidFormat
	}

	value := signedValue[:rightmostSep]
	signature := signedValue[rightmostSep+1:]

	if s.validateSignature(value, signature) {
		return value, nil
	}

	return nil, ErrInvalidSignature
}

// Validate returns true if signedValue is valid.
func (s *Signer) Validate(signedValue []byte) bool {
	_, err := s.Unsign(signedValue)
	return err == nil
}