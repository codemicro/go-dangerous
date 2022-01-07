package dangerous

import (
	"fmt"
	"testing"
)

func Test_Sign(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSigner(WithKey(key))
	if err != nil {
		t.Fatal(err)
	}

	c, err := s.Sign([]byte("hello world"))

	fmt.Printf("With key: %#v\n", string(key))
	fmt.Printf("Signed: %#v %v\n", string(c), err)

	u, err := s.Unsign(c)
	fmt.Printf("Unsigned: %#v %v\n", string(u), err)
	fmt.Printf("Valid: %v\n", s.Validate(c))
}
