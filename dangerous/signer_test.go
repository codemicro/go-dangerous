package dangerous

import (
	"fmt"
	"testing"
	"time"
)

func Test_Sign(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewTimestampSigner(WithKey(key))
	if err != nil {
		t.Fatal(err)
	}

	c, err := s.Sign([]byte("hello world"))

	fmt.Printf("With key: %#v\n", string(key))
	fmt.Printf("Signed: %#v %v\n", string(c), err)

	maxAge := NoMaxAge
	u, y, err := s.Unsign(c, maxAge)

	fmt.Printf("Unsigned: %#v %s %v\n", string(u), y.Format(time.RFC1123Z), err)
	fmt.Printf("Valid: %v\n", s.Validate(c, maxAge))
}
