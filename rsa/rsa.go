package rsa

import (
	"fmt"
	"math/big"
)

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	N *big.Int
	D *big.Int
}

func Setup(p big.Int, q big.Int) (*PublicKey, *PrivateKey) {
	n := new(big.Int).Mul(&p, &q)

	pSub1 := new(big.Int).Sub(&p, big.NewInt(1))
	qSub1 := new(big.Int).Sub(&q, big.NewInt(1))
	phi := new(big.Int).Mul(pSub1, qSub1)

	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)

	publicKey := &PublicKey{
		N: n,
		E: e,
	}

	privateKey := &PrivateKey{
		N: n,
		D: d,
	}

	return publicKey, privateKey
}

func Encrypt(publicKey *PublicKey, message []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(message)

	if m.Cmp(publicKey.N) >= 0 {
		return nil, fmt.Errorf("message too large for key size")
	}

	c := new(big.Int).Exp(m, publicKey.E, publicKey.N)
	return c.Bytes(), nil
}

func Decrypt(privateKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)

	if c.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("ciphertext too large for key size")
	}

	m := new(big.Int).Exp(c, privateKey.D, privateKey.N)
	return m.Bytes(), nil
}
