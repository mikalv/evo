package elgamal

import (
	"crypto/cipher"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/random"
)

// Shuffle ElGamal pairs vectors using the Fisher-Yates algorithm.
// Returns permuted pair vectors, the permutation array and the blinding factors.
func Permute(group abstract.Group, g, w abstract.Point, A, B []abstract.Point,
	stream cipher.Stream) (S, T []abstract.Point, pi []int, beta []abstract.Scalar) {

	k := len(A)
	if k != len(B) {
		panic("Pair vectors have inconsistent length")
	}

	pi = make([]int, k)
	for i := 0; i < k; i++ {
		pi[i] = i
	}

	for i := k - 1; i > 0; i-- {
		j := int(random.Uint64(stream) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}

	beta = make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		beta[i] = group.Scalar().Pick(stream)
	}

	S = make([]abstract.Point, k)
	T = make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		S[i] = group.Point().Mul(g, beta[pi[i]])
		S[i].Add(S[i], A[pi[i]])
		T[i] = group.Point().Mul(w, beta[pi[i]])
		T[i].Add(T[i], B[pi[i]])
	}

	return
}
