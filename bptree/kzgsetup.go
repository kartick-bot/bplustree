package bptree

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// newKZGSRS creates one KZG SRS for the entire B+ tree.
//
// size is the maximum number of polynomial coefficients
// that we need to commit to.
//
// For a B+ tree of order b:
//
//	max leaf entries = b - 1
//
// and therefore:
//
//	max polynomial coefficients = b - 1
//
// The secret alpha is generated randomly and is NOT
// stored in the Tree.
func newKZGSRS(
	size uint64,
	modulus *big.Int,
) (*kzg.SRS, error) {

	if modulus == nil {
		return nil, fmt.Errorf(
			"cannot create KZG SRS: modulus is nil",
		)
	}

	if size < 2 {
		return nil, fmt.Errorf(
			"KZG SRS size must be at least 2",
		)
	}

	// Sample alpha from:
	//
	//     2 <= alpha < p
	//
	// Avoiding 0 and 1 prevents trivial choices.
	pMinusTwo := new(big.Int).Sub(
		modulus,
		big.NewInt(2),
	)

	r, err := rand.Int(
		rand.Reader,
		pMinusTwo,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate KZG setup randomness: %w",
			err,
		)
	}

	// r is in [0, p-3].
	//
	// Therefore alpha is in [2, p-1].
	alpha := new(big.Int).Add(
		r,
		big.NewInt(2),
	)

	srs, err := kzg.NewSRS(
		size,
		alpha,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to create KZG SRS: %w",
			err,
		)
	}

	return srs, nil
}
