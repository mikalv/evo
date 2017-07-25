package sato

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/proof"

	"github.com/qantik/evo/backend/crypto/elgamal"
)

type sigma1 struct {
	U []abstract.Point
	V []abstract.Point
}

type sigma2 struct {
	Mask abstract.Scalar
}

type sigma3 struct {
	Lambda []int
	Gamma  []abstract.Scalar
}

type Protocol struct {
	group     abstract.Group
	k         int
	prover1   sigma1
	verifier2 sigma2
	prover3   sigma3
}

func (protocol *Protocol) init(group abstract.Group, k int) {
	protocol.group = group
	protocol.k = k
	protocol.prover1.U = make([]abstract.Point, k)
	protocol.prover1.V = make([]abstract.Point, k)
	protocol.verifier2.Mask = group.Scalar().Zero() // TODO
	protocol.prover3.Lambda = make([]int, k)
	protocol.prover3.Gamma = make([]abstract.Scalar, k)
}

func (protocol *Protocol) prove(pi []int, g, w abstract.Point, beta []abstract.Scalar,
	A, B []abstract.Point, stream cipher.Stream, context proof.ProverContext) error {

	U, V, lambda, gamma := elgamal.Permute(protocol.group, g, w, A, B, stream)
	protocol.prover1.U = U
	protocol.prover1.V = V
	if err := context.Put(protocol.prover1); err != nil {
		return err
	}

	if err := context.PubRand(protocol.verifier2); err != nil {
		return err
	}

	// TODO P step 3
	protocol.prover3.Lambda = lambda
	protocol.prover3.Gamma = gamma
	if err := context.Put(protocol.prover3); err != nil {
		return err
	}

	return nil
}

func (protocol *Protocol) verify(g, w abstract.Point, A, B, S, T []abstract.Point,
	context proof.VerifierContext) error {

	if err := context.Get(protocol.prover1); err != nil {
		return err
	}

	if err := context.PubRand(protocol.verifier2); err != nil {
		return err
	}

	if err := context.Get(protocol.prover3); err != nil {
		return err
	}

	// Verification
	lambda := protocol.prover3.Lambda
	gamma := protocol.prover3.Gamma
	for i := 0; i < protocol.k; i++ {
		alpha := protocol.group.Point().Mul(g, gamma[lambda[i]])
		alpha.Add(alpha, A[lambda[i]])
		if !alpha.Equal(protocol.prover1.U[i]) {
			return errors.New("Sato-Kilian: Verification failed on alpha field")
		}

		beta := protocol.group.Point().Mul(w, gamma[lambda[i]])
		beta.Add(beta, B[lambda[i]])
		if !beta.Equal(protocol.prover1.V[i]) {
			return errors.New("Sato-Kilian: Verification failed on beta field")
		}
	}

	return nil
}

func Shuffle(group abstract.Group, g, w abstract.Point, A, B []abstract.Point,
	stream cipher.Stream) (S, T []abstract.Point, prover proof.Prover) {

	if len(A) != len(B) || len(A) <= 1 {
		panic("Invalid vector sizes.")
	}

	protocol := Protocol{}
	protocol.init(group, len(A))

	S, T, pi, beta := elgamal.Permute(group, g, w, A, B, stream)
	prover = func(context proof.ProverContext) error {
		return protocol.prove(pi, g, w, beta, A, B, stream, context)
	}

	return
}

func Verifier(group abstract.Group, g, w abstract.Point,
	A, B, S, T []abstract.Point) proof.Verifier {

	k := len(A)
	if k <= 1 || k != len(B) || k != len(S) || k != len(T) {
		panic("Invalid vector sizes.")
	}

	protocol := Protocol{}
	protocol.init(group, len(A))

	return func(context proof.VerifierContext) error {
		return protocol.verify(g, w, A, B, S, T, context)
	}
}
