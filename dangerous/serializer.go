package dangerous

import (
	"encoding/json"
	"time"
)

type Marshaler func(interface{}) ([]byte, error)
type Unmarshaler func([]byte, interface{}) error

type Serializer struct {
	Signer            *Signer
	MarshalFunction   Marshaler
	UnmarshalFunction Unmarshaler
}

func NewSerializer(signerOptions ...SignerOption) (*Serializer, error) {
	signer, err := NewSigner(signerOptions...)
	if err != nil {
		return nil, err
	}
	return &Serializer{
		Signer:            signer,
		MarshalFunction:   json.Marshal,
		UnmarshalFunction: json.Unmarshal,
	}, nil
}

func (s *Serializer) Marshal(x interface{}) ([]byte, error) {
	asBytes, err := s.MarshalFunction(x)
	if err != nil {
		return nil, err
	}
	return s.Signer.Sign(asBytes)
}

func (s *Serializer) Unmarshal(signedData []byte, x interface{}) error {
	value, err := s.Signer.Unsign(signedData)
	if err != nil {
		return err
	}
	return s.UnmarshalFunction(value, x)
}

type TimestampSerializer struct {
	Signer            *TimestampSigner
	MarshalFunction   Marshaler
	UnmarshalFunction Unmarshaler
}

func NewTimestampSerializer(signerOptions ...SignerOption) (*TimestampSerializer, error) {
	signer, err := NewTimestampSigner(signerOptions...)
	if err != nil {
		return nil, err
	}
	return &TimestampSerializer{
		Signer:            signer,
		MarshalFunction:   json.Marshal,
		UnmarshalFunction: json.Unmarshal,
	}, nil
}

func (t *TimestampSerializer) Marshal(x interface{}) ([]byte, error) {
	asBytes, err := t.MarshalFunction(x)
	if err != nil {
		return nil, err
	}
	return t.Signer.Sign(asBytes)
}

func (t *TimestampSerializer) Unmarshal(signedData []byte, x interface{}, maxAge time.Duration) (time.Time, error) {
	value, createdAt, err := t.Signer.Unsign(signedData, maxAge)
	if err != nil {
		return time.Time{}, err
	}
	return createdAt, t.UnmarshalFunction(value, x)
}

type URLSafeSerializer struct {
	Signer            *Signer
	MarshalFunction   Marshaler
	UnmarshalFunction Unmarshaler
}

func NewURLSafeSerializer(signerOptions ...SignerOption) (*URLSafeSerializer, error) {
	signer, err := NewSigner(signerOptions...)
	if err != nil {
		return nil, err
	}
	return &URLSafeSerializer{
		Signer:            signer,
		MarshalFunction:   json.Marshal,
		UnmarshalFunction: json.Unmarshal,
	}, nil
}

func (u *URLSafeSerializer) Marshal(x interface{}) ([]byte, error) {
	asBytes, err := u.MarshalFunction(x)
	if err != nil {
		return nil, err
	}

	var compressed bool
	if comp, err := zlibCompress(asBytes); err != nil {
		return nil, err
	} else if len(comp) < len(asBytes) {
		asBytes = comp
		compressed = true
	}

	asBase64 := base64Encode(asBytes)

	if compressed {
		asBase64 = append([]byte{'.'}, asBase64...)
	}

	return u.Signer.Sign(asBase64)
}

func (u *URLSafeSerializer) Unmarshal(signedData []byte, x interface{}) error {
	valueAsBase64, err := u.Signer.Unsign(signedData)
	if err != nil {
		return err
	}

	var compressed bool
	if valueAsBase64[0] == '.' {
		// A leading point is used to indicate that the data was compressed.
		compressed = true
		valueAsBase64 = valueAsBase64[1:]
	}

	value, err := decodeBase64(valueAsBase64)
	if err != nil {
		return err
	}

	if compressed {
		y, err := zlibDecompress(value)
		if err != nil {
			return err
		}
		value = y
	}

	return u.UnmarshalFunction(value, x)
}
