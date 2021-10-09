package cp

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
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

func TestChallenge05(t *testing.T) {
	t.Parallel()
	s := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	want := helperHexDecode(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	got := XORCycle([]byte(s), []byte(key))
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestHamming(t *testing.T) {
	t.Parallel()
	var (
		a    = "this is a test"
		b    = "wokka wokka!!!"
		want = 37
	)
	got := Hamming([]byte(a), []byte(b))
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func helperReadBase64Ciphertext(tb testing.TB, path string) []byte {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		tb.Fatal(err)
	}
	return ct
}

func TestChallenge06(t *testing.T) {
	t.Parallel()
	ct := helperReadBase64Ciphertext(t, "testdata/6.txt")
	want := []byte("Terminator X: Bring the noise")

	got := BreakRepeatingKeyXOR(ct)
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	t.Logf("%s", XORCycle(ct, got))
}

func TestChallenge07(t *testing.T) {
	t.Parallel()
	ct := helperReadBase64Ciphertext(t, "testdata/7.txt")
	key := "YELLOW SUBMARINE"

	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	decrypter := NewECBDecrypter(cipher)

	got := make([]byte, len(ct))
	decrypter.CryptBlocks(got, ct)

	if !strings.HasPrefix(string(got), "I'm back and I'm ringin' the bell") {
		t.Errorf("got %q", got)
	}
}

func TestChallenge08(t *testing.T) {
	t.Parallel()
	ct := helperReadHexCiphertexts(t, "testdata/8.txt")
	// 08649af70dc06f4f and d5d2d69c744cd283 both appear twice at possible offsets
	want := helperHexDecode(t, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
	bs := 16

	got, ok := DetectECB(ct, bs)
	if !ok {
		t.Error("no ECB ciphertext found")
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}
