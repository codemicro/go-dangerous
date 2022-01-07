package dangerous

import (
	"fmt"
	"testing"
	"time"
)

func Test_Serialize(t *testing.T) {
	s, err := NewTimestampSerializer(WithKey([]byte("POTATO!!!!")))
	if err != nil {
		t.Fatal(err)
	}

	rawData := map[string]string{"ghghghghghghghghgh": "fgfgfvffffffffffffffffffffffffff"}
	x, err := s.Marshal(rawData)
	fmt.Println("Encoded:", string(x), err)

	out := make(map[string]string)
	b, err := s.Unmarshal(x, &out, 0)
	fmt.Println(out, b.Format(time.RFC1123), err)

	fmt.Println()

	rawData = map[string]string{"b": "a"}
	x, err = s.Marshal(rawData)
	fmt.Println("Encoded:", string(x), err)

	out = make(map[string]string)
	b, err = s.Unmarshal(x, &out, 0)
	fmt.Println(out,b.Format(time.RFC1123), err)
}
