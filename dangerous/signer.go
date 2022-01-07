package dangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"time"
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
	ErrMissingTimestamp = errors.New("dangerous: missing timestamp")
	ErrSignatureExpired = errors.New("dangerous: signature expired")
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
	// TODO: morederivation modes

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

// Validate returns true if signedValue is valid.func (s *Signer)
func (s *Signer) Validate(signedValue []byte) bool {
	_, err := s.Unsign(signedValue)
	return err == nil
}

type TimestampSigner struct {
	*Signer
}

func NewTimestampSigner(opts ...SignerOption) (*TimestampSigner, error) {
	if s, err := NewSigner(opts...); err != nil {
		return nil, err
	} else {
		return &TimestampSigner{Signer: s}, nil
	}
}

func (t *TimestampSigner) Sign(data []byte) ([]byte, error) {
	data = append(data, t.Separator)
	data = append(data, encodeBase64(
		int64ToBytes(
			time.Now().Unix(),
		),
	)...)

	return t.Signer.Sign(data)
}

const NoMaxAge time.Duration = 0

func (t *TimestampSigner) Unsign(signedValue []byte, maxAge time.Duration) ([]byte, time.Time, error) {
	value, err := t.Signer.Unsign(signedValue)
	if err != nil {
		return nil, time.Time{}, err
	}

	rightmostSeperator := bytesRIndex(value, t.Separator)
	if rightmostSeperator == -1 {
		return nil, time.Time{}, ErrMissingTimestamp
	}

	base64TimestampBytes := value[rightmostSeperator+1:]
	value = value[:rightmostSeperator]

	timestampBytes, err := decodeBase64(base64TimestampBytes)
	if err != nil {
		return nil, time.Time{}, err
	}

	createdAtTimestamp := time.Unix(bytesToInt64(timestampBytes), 0)

	if time.Since(createdAtTimestamp) > maxAge && maxAge != NoMaxAge {
		return nil, createdAtTimestamp, ErrSignatureExpired
	}

	return value, createdAtTimestamp, nil
}

// Validate returns true if signedValue is valid.func (s *Signer)
func (t *TimestampSigner) Validate(signedValue []byte, maxAge time.Duration) bool {
	_, _, err := t.Unsign(signedValue, maxAge)
	return err == nil
}
