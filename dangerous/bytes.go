package dangerous

// bytesRIndex searches b for char going from right-to-left.
// returns -1 if not found.
func bytesRIndex(b []byte, char byte) int {
	for i := len(b) - 1; i >= 0; i -= 1 {
		if b[i] == char {
			return i
		}
	}
	return -1
}