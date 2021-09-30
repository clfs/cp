package cp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func HexToBase64(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func HexXOR(a, b string) (string, error) {
	if len(a) != len(b) {
		return "", fmt.Errorf("different lengths")
	}
	ba, err := hex.DecodeString(a)
	if err != nil {
		return "", err
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(XOR(ba, bb)), nil
}

func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("different lengths")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
