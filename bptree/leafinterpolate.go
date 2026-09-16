package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// interpolateAtPoints performs Lagrange interpolation over Z_p.
//
// points[i] is the evaluation point x_i.
// values[i] is f(x_i).
//
// It returns coefficients:
//
//	a_0, a_1, ..., a_d
//
// representing:
//
//	f(X) = a_0 + a_1 X + ... + a_d X^d.
func interpolateAtPoints(
	points []uint64,
	values []*big.Int,
	modulus *big.Int,
) ([]fr.Element, error) {

	if len(points) != len(values) {
		return nil, fmt.Errorf(
			"%d evaluation points but %d values",
			len(points),
			len(values),
		)
	}

	if len(points) == 0 {
		return nil, fmt.Errorf(
			"cannot interpolate empty input",
		)
	}

	n := len(points)

	// Polynomial coefficients in big.Int form.
	result :=
		make(
			[]*big.Int,
			n,
		)

	for i := range result {
		result[i] = new(big.Int)
	}

	// ============================================================
	// Lagrange interpolation:
	//
	//              X - x_j
	// L_i(X) = Π -----------
	//          j!=i x_i-x_j
	//
	// f(X) = Σ y_i L_i(X)
	// ============================================================

	for i := 0; i < n; i++ {

		if values[i] == nil {
			return nil, fmt.Errorf(
				"nil value at position %d",
				i,
			)
		}

		// Numerator polynomial starts as 1.
		numerator :=
			[]*big.Int{
				big.NewInt(1),
			}

		denominator :=
			big.NewInt(1)

		xi :=
			new(big.Int).SetUint64(
				points[i],
			)

		xi.Mod(
			xi,
			modulus,
		)

		for j := 0; j < n; j++ {

			if i == j {
				continue
			}

			xj :=
				new(big.Int).SetUint64(
					points[j],
				)

			xj.Mod(
				xj,
				modulus,
			)

			if xi.Cmp(xj) == 0 {
				return nil, fmt.Errorf(
					"duplicate evaluation point %d",
					points[i],
				)
			}

			// Multiply numerator by:
			//
			//   (X - x_j)
			factor0 :=
				new(big.Int).Neg(
					xj,
				)

			factor0.Mod(
				factor0,
				modulus,
			)

			next :=
				make(
					[]*big.Int,
					len(numerator)+1,
				)

			for k := range next {
				next[k] = new(big.Int)
			}

			for k := range numerator {

				// Constant contribution:
				//
				// numerator[k] * (-x_j)
				temp :=
					new(big.Int).Mul(
						numerator[k],
						factor0,
					)

				next[k].Add(
					next[k],
					temp,
				)

				next[k].Mod(
					next[k],
					modulus,
				)

				// X contribution:
				next[k+1].Add(
					next[k+1],
					numerator[k],
				)

				next[k+1].Mod(
					next[k+1],
					modulus,
				)
			}

			numerator = next

			// denominator *= (x_i - x_j)
			diff :=
				new(big.Int).Sub(
					xi,
					xj,
				)

			diff.Mod(
				diff,
				modulus,
			)

			denominator.Mul(
				denominator,
				diff,
			)

			denominator.Mod(
				denominator,
				modulus,
			)
		}

		denominatorInverse :=
			new(big.Int).ModInverse(
				denominator,
				modulus,
			)

		if denominatorInverse == nil {
			return nil, fmt.Errorf(
				"could not invert interpolation denominator at position %d",
				i,
			)
		}

		scale :=
			new(big.Int).Mul(
				values[i],
				denominatorInverse,
			)

		scale.Mod(
			scale,
			modulus,
		)

		for k := range numerator {

			term :=
				new(big.Int).Mul(
					numerator[k],
					scale,
				)

			result[k].Add(
				result[k],
				term,
			)

			result[k].Mod(
				result[k],
				modulus,
			)
		}
	}

	coefficients :=
		make(
			[]fr.Element,
			n,
		)

	for i := range result {
		coefficients[i].SetBigInt(
			result[i],
		)
	}

	return coefficients, nil
}
