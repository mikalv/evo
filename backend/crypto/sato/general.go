package sato

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/proof"

	"github.com/qantik/evo/backend/crypto/elgamal"
)

type ega1 struct {
	C1 []abstract.Point
	C2 []abstract.Point
}

type ega2 struct {
	Mask abstract.Scalar
}

type ega3 struct {
	Zlambda []int
	Zt      []abstract.Scalar
}

type PairShuffle struct {
	group abstract.Group
	k     int
	p1    ega1
	v2    ega2
	p3    ega3
}

func (ps *PairShuffle) Init(group abstract.Group, k int) *PairShuffle {
	if k <= 1 {
		panic("Cannot shuffle permutation of size <= 1")
	}

	ps.group = group
	ps.k = k
	ps.p1.C1 = make([]abstract.Point, k)
	ps.p1.C2 = make([]abstract.Point, k)
	ps.v2.Mask = group.Scalar().Zero() // TODO
	ps.p3.Zlambda = make([]int, k)
	ps.p3.Zt = make([]abstract.Scalar, k)

	return ps
}

func (ps *PairShuffle) Prove(pi []int, g, w abstract.Point, beta []abstract.Scalar,
	A1, A2 []abstract.Point, stream cipher.Stream, ctx proof.ProverContext) error {

	k := ps.k
	if k != len(pi) || k != len(beta) || k != len(A1) || k != len(A2) {
		panic("Mismatched vector lengths.")
	}

	// P step 1
	C1, C2, lambda, t := elgamal.Permute(ps.group, g, w, A1, A2, stream)
	ps.p1.C1 = C1
	ps.p1.C2 = C2

	if err := ctx.Put(ps.p1); err != nil {
		return err
	}

	// V step 2
	if err := ctx.PubRand(ps.v2); err != nil {
		return err
	}

	// TODO P step 3
	ps.p3.Zlambda = lambda
	ps.p3.Zt = t
	if err := ctx.Put(ps.p3); err != nil {
		return err
	}

	return nil
}

func (ps *PairShuffle) Verify(g, w abstract.Point, A1, A2, B1, B2 []abstract.Point,
	ctx proof.VerifierContext) error {

	k := ps.k
	if k != len(A1) || k != len(A2) || k != len(B1) || k != len(B2) {
		panic("Mismatched vector lengths.")
	}

	// P step 1
	if err := ctx.Get(ps.p1); err != nil {
		return err
	}

	// V step 2
	if err := ctx.PubRand(ps.v2); err != nil {
		return err
	}

	// V step 3
	if err := ctx.Get(ps.p3); err != nil {
		return err
	}

	// Verification
	lambda := ps.p3.Zlambda
	t := ps.p3.Zt
	for i := 0; i < k; i++ {
		V1 := ps.group.Point().Mul(g, t[lambda[i]])
		V1.Add(V1, A1[lambda[i]])

		if !V1.Equal(ps.p1.C1[i]) {
			return errors.New("Invalid PairShuffleProof")
		}

		V2 := ps.group.Point().Mul(w, t[lambda[i]])
		V2.Add(V2, A2[lambda[i]])

		if !V2.Equal(ps.p1.C2[i]) {
			return errors.New("Invalid PairShuffleProof")
		}
	}

	return nil
}

func Shuffle(group abstract.Group, g, w abstract.Point, A, B []abstract.Point,
	stream cipher.Stream) (B1, B2 []abstract.Point, prover proof.Prover) {

	ps := PairShuffle{}
	ps.Init(group, len(A))

	B1, B2, pi, beta := elgamal.Permute(group, g, w, A, B, stream)
	prover = func(ctx proof.ProverContext) error {
		return ps.Prove(pi, g, w, beta, A, B, stream, ctx)
	}

	return
}

func Verifier(group abstract.Group, g, w abstract.Point,
	A1, A2, B1, B2 []abstract.Point) proof.Verifier {

	ps := PairShuffle{}
	ps.Init(group, len(A1))

	return func(ctx proof.VerifierContext) error {
		return ps.Verify(g, w, A1, A2, B1, B2, ctx)
	}
}
