package neff

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/proof"
	"github.com/qantik/evo/backend/crypto/elgamal"
)

// P (Prover) step 1: public commitments
type ega1 struct {
	Gamma            abstract.Point
	A, C, U, W       []abstract.Point
	Lambda1, Lambda2 abstract.Point
}

// V (Verifier) step 2: random challenge t
type ega2 struct {
	Zrho []abstract.Scalar
}

// P step 3: Theta vectors
type ega3 struct {
	D []abstract.Point
}

// V step 4: random challenge c
type ega4 struct {
	Zlambda abstract.Scalar
}

// P step 5: alpha vector
type ega5 struct {
	Zsigma []abstract.Scalar
	Ztau   abstract.Scalar
}

// P and V, step 6: simple k-shuffle proof
type ega6 struct {
	SimpleShuffle
}

type PairShuffle struct {
	grp abstract.Group
	k   int
	p1  ega1
	v2  ega2
	p3  ega3
	v4  ega4
	p5  ega5
	pv6 SimpleShuffle
}

func (ps *PairShuffle) Init(grp abstract.Group, k int) *PairShuffle {
	if k <= 1 {
		panic("can't shuffle permutation of size <= 1")
	}

	ps.grp = grp
	ps.k = k
	ps.p1.A = make([]abstract.Point, k)
	ps.p1.C = make([]abstract.Point, k)
	ps.p1.U = make([]abstract.Point, k)
	ps.p1.W = make([]abstract.Point, k)
	ps.v2.Zrho = make([]abstract.Scalar, k)
	ps.p3.D = make([]abstract.Point, k)
	ps.p5.Zsigma = make([]abstract.Scalar, k)
	ps.pv6.Init(grp, k)

	return ps
}

func (ps *PairShuffle) Prove(
	pi []int, g, h abstract.Point, beta []abstract.Scalar,
	X, Y []abstract.Point, rand cipher.Stream,
	ctx proof.ProverContext) error {

	grp := ps.grp
	k := ps.k
	if k != len(pi) || k != len(beta) {
		panic("mismatched vector lengths")
	}

	// Compute pi^-1 inverse permutation
	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	// P step 1
	p1 := &ps.p1
	z := grp.Scalar()

	// pick random secrets
	u := make([]abstract.Scalar, k)
	w := make([]abstract.Scalar, k)
	a := make([]abstract.Scalar, k)
	var tau0, nu, gamma abstract.Scalar
	ctx.PriRand(u, w, a, &tau0, &nu, &gamma)

	// compute public commits
	p1.Gamma = grp.Point().Mul(g, gamma)
	wbeta := grp.Scalar()
	wbetasum := grp.Scalar().Set(tau0)
	p1.Lambda1 = grp.Point().Null()
	p1.Lambda2 = grp.Point().Null()
	XY := grp.Point()
	wu := grp.Scalar()
	for i := 0; i < k; i++ {
		p1.A[i] = grp.Point().Mul(g, a[i])
		p1.C[i] = grp.Point().Mul(g, z.Mul(gamma, a[pi[i]]))
		p1.U[i] = grp.Point().Mul(g, u[i])
		p1.W[i] = grp.Point().Mul(g, z.Mul(gamma, w[i]))
		wbetasum.Add(wbetasum, wbeta.Mul(w[i], beta[pi[i]]))
		p1.Lambda1.Add(p1.Lambda1, XY.Mul(X[i],
			wu.Sub(w[piinv[i]], u[i])))
		p1.Lambda2.Add(p1.Lambda2, XY.Mul(Y[i],
			wu.Sub(w[piinv[i]], u[i])))
	}
	p1.Lambda1.Add(p1.Lambda1, XY.Mul(g, wbetasum))
	p1.Lambda2.Add(p1.Lambda2, XY.Mul(h, wbetasum))
	if err := ctx.Put(p1); err != nil {
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Mul(g, v2.Zrho[i])
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	b := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		b[i] = grp.Scalar().Sub(v2.Zrho[i], u[i])
	}
	d := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		d[i] = grp.Scalar().Mul(gamma, b[pi[i]])
		p3.D[i] = grp.Point().Mul(g, d[i])
	}
	if err := ctx.Put(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	r := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		r[i] = grp.Scalar().Add(a[i], z.Mul(v4.Zlambda, b[i]))
	}
	s := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		s[i] = grp.Scalar().Mul(gamma, r[pi[i]])
	}
	p5.Ztau = grp.Scalar().Neg(tau0)
	for i := 0; i < k; i++ {
		p5.Zsigma[i] = grp.Scalar().Add(w[i], b[pi[i]])
		p5.Ztau.Add(p5.Ztau, z.Mul(b[i], beta[i]))
	}
	if err := ctx.Put(p5); err != nil {
		return err
	}

	// P,V step 6: embedded simple k-shuffle proof
	return ps.pv6.Prove(g, gamma, r, s, rand, ctx)
}

func (ps *PairShuffle) Verify(
	g, h abstract.Point, X, Y, Xbar, Ybar []abstract.Point,
	ctx proof.VerifierContext) error {

	grp := ps.grp
	k := ps.k
	if len(X) != k || len(Y) != k || len(Xbar) != k || len(Ybar) != k {
		panic("mismatched vector lengths")
	}

	// P step 1
	p1 := &ps.p1
	if err := ctx.Get(p1); err != nil {
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Mul(g, v2.Zrho[i])
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	if err := ctx.Get(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	if err := ctx.Get(p5); err != nil {
		return err
	}

	// P,V step 6: simple k-shuffle
	if err := ps.pv6.Verify(g, p1.Gamma, ctx); err != nil {
		return err
	}

	// V step 7
	Phi1 := grp.Point().Null()
	Phi2 := grp.Point().Null()
	P := grp.Point()
	Q := grp.Point()
	for i := 0; i < k; i++ {
		Phi1 = Phi1.Add(Phi1, P.Mul(Xbar[i], p5.Zsigma[i]))
		Phi1 = Phi1.Sub(Phi1, P.Mul(X[i], v2.Zrho[i]))
		Phi2 = Phi2.Add(Phi2, P.Mul(Ybar[i], p5.Zsigma[i]))
		Phi2 = Phi2.Sub(Phi2, P.Mul(Y[i], v2.Zrho[i]))
		if !P.Mul(p1.Gamma, p5.Zsigma[i]).Equal(
			Q.Add(p1.W[i], p3.D[i])) {
			return errors.New("invalid PairShuffleProof")
		}
	}

	if !P.Add(p1.Lambda1, Q.Mul(g, p5.Ztau)).Equal(Phi1) ||
		!P.Add(p1.Lambda2, Q.Mul(h, p5.Ztau)).Equal(Phi2) {
		return errors.New("invalid PairShuffleProof")
	}

	return nil
}

func Shuffle(group abstract.Group, g, h abstract.Point, X, Y []abstract.Point,
	rand cipher.Stream) (XX, YY []abstract.Point, P proof.Prover) {

	k := len(X)
	if k != len(Y) {
		panic("X,Y vectors have inconsistent length")
	}

	ps := PairShuffle{}
	ps.Init(group, k)

	Xbar, Ybar, pi, beta := elgamal.Permute(group, g, h, X, Y, rand)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, g, h, beta, X, Y, rand, ctx)
	}

	return Xbar, Ybar, prover
}

func Verifier(group abstract.Group, g, h abstract.Point,
	X, Y, Xbar, Ybar []abstract.Point) proof.Verifier {

	ps := PairShuffle{}
	ps.Init(group, len(X))

	return func(ctx proof.VerifierContext) error {
		return ps.Verify(g, h, X, Y, Xbar, Ybar, ctx)
	}
}
