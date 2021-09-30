package cp

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestChallenge01(t *testing.T) {
	t.Parallel()
	s := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got, err := HexToBase64(s)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestChallenge02(t *testing.T) {
	t.Parallel()
	var (
		a    = "1c0111001f010100061a024b53535009181c"
		b    = "686974207468652062756c6c277320657965"
		want = "746865206b696420646f6e277420706c6179"
	)
	got, err := HexXOR(a, b)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func helperHexDecode(tb testing.TB, s string) []byte {
	tb.Helper()
	got, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return got
}

func TestChallenge03(t *testing.T) {
	t.Parallel()
	var (
		ct   = helperHexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		want = byte(88)
	)
	got := FindXORKey(ct)
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
	t.Logf("%s", XORRepeat(ct, got))
}

func helperReadHexCiphertexts(tb testing.TB, path string) [][]byte {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	cts := bytes.Split(data, []byte("\n"))
	var got [][]byte
	for _, ct := range cts {
		got = append(got, helperHexDecode(tb, string(ct)))
	}
	return got
}

func TestChallenge04(t *testing.T) {
	t.Parallel()
	cts := helperReadHexCiphertexts(t, "testdata/4.txt")
	want := helperHexDecode(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")

	got := DetectSingleXOR(cts)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}

	t.Logf("%s", XORRepeat(got, FindXORKey(got)))
}
