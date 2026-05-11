package rsa

import (
	"math/big"
	"testing"
)

// Small primes for testing (not secure, just for unit tests)
var (
	p = *big.NewInt(61)
	q = *big.NewInt(53)
)

// Large primes for realistic key size tests
var (
	bigP, _ = new(big.Int).SetString("104729", 10)
	bigQ, _ = new(big.Int).SetString("104723", 10)
)

func TestSetup(t *testing.T) {
	pub, priv := Setup(p, q)

	expectedN := new(big.Int).Mul(big.NewInt(61), big.NewInt(53)) // 3233
	if pub.N.Cmp(expectedN) != 0 {
		t.Errorf("public key N = %v, want %v", pub.N, expectedN)
	}
	if priv.N.Cmp(expectedN) != 0 {
		t.Errorf("private key N = %v, want %v", priv.N, expectedN)
	}
	if pub.E.Cmp(big.NewInt(65537)) != 0 {
		t.Errorf("public key E = %v, want 65537", pub.E)
	}
	if priv.D == nil {
		t.Fatal("private key D is nil")
	}

	// Verify e*d ≡ 1 (mod phi)
	pSub1 := new(big.Int).Sub(big.NewInt(61), big.NewInt(1))
	qSub1 := new(big.Int).Sub(big.NewInt(53), big.NewInt(1))
	phi := new(big.Int).Mul(pSub1, qSub1)
	ed := new(big.Int).Mul(pub.E, priv.D)
	ed.Mod(ed, phi)
	if ed.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("e*d mod phi = %v, want 1", ed)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	pub, priv := Setup(*bigP, *bigQ)

	message := []byte("hi")
	ciphertext, err := Encrypt(pub, message)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	plaintext, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if string(plaintext) != string(message) {
		t.Errorf("Decrypt(%v) = %q, want %q", ciphertext, plaintext, message)
	}
}

func TestEncryptDecryptSingleByte(t *testing.T) {
	pub, priv := Setup(p, q)

	message := []byte{42}
	ciphertext, err := Encrypt(pub, message)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	plaintext, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if len(plaintext) != 1 || plaintext[0] != 42 {
		t.Errorf("Decrypt = %v, want [42]", plaintext)
	}
}

func TestEncryptMessageTooLarge(t *testing.T) {
	pub, _ := Setup(p, q) // N = 3233

	// Message as big integer >= N
	m := new(big.Int).Add(pub.N, big.NewInt(1))
	_, err := Encrypt(pub, m.Bytes())
	if err == nil {
		t.Error("expected error for message >= N, got nil")
	}
}

func TestDecryptCiphertextTooLarge(t *testing.T) {
	_, priv := Setup(p, q) // N = 3233

	c := new(big.Int).Add(priv.N, big.NewInt(1))
	_, err := Decrypt(priv, c.Bytes())
	if err == nil {
		t.Error("expected error for ciphertext >= N, got nil")
	}
}

func TestEncryptDeterministic(t *testing.T) {
	pub, _ := Setup(*bigP, *bigQ)

	message := []byte("test")
	c1, err1 := Encrypt(pub, message)
	c2, err2 := Encrypt(pub, message)
	if err1 != nil || err2 != nil {
		t.Fatalf("Encrypt errors: %v, %v", err1, err2)
	}

	if string(c1) != string(c2) {
		t.Error("Encrypt is not deterministic for same input")
	}
}
