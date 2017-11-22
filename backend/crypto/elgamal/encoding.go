package elgamal

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

// Canonical ElGamal encryption. Returning encryption pair points.
// https://en.wikipedia.org/wiki/ElGamal_encryption#Encryption
func Encrypt(suite abstract.Suite, public abstract.Point, message []byte) (
	alpha, beta abstract.Point) {

	// Map message onto group element
	m, _ := suite.Point().Pick(message, random.Stream)

	y := suite.Scalar().Pick(random.Stream)
	alpha = suite.Point().Mul(nil, y)
	s := suite.Point().Mul(public, y)
	beta = s.Add(s, m)

	return
}

// Canonical ElGamal decryption using the encryption pair points.
// https://en.wikipedia.org/wiki/ElGamal_encryption#Decryption
func Decrypt(suite abstract.Suite, secret abstract.Scalar, alpha, beta abstract.Point) (
	message []byte, err error) {

	s := suite.Point().Mul(alpha, secret)
	m := suite.Point().Sub(beta, s)
	message, err = m.Data()

	return
}
