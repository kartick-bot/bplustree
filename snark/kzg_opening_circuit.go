package snark

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdkzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

// KZGOpeningCircuit verifies one BN254 KZG opening proof
// inside a gnark circuit.
//
// It checks:
//
//	e(C - yG1, G2)
//	    =
//	e(pi, [tau]G2 - zG2)
//
// where:
//
//	C  = polynomial commitment
//	y  = claimed polynomial evaluation
//	pi = KZG opening proof
//	z  = evaluation point
//
// For this first milestone, all values are circuit witnesses.
// We will decide the final public/private boundary when we
// integrate the circuit with the B+ tree.
type KZGOpeningCircuit struct {
	// KZG verification key for the node-specific SRS.
	VerifyingKey stdkzg.VerifyingKey[
		sw_bn254.G1Affine,
		sw_bn254.G2Affine,
	]

	// Commitment C = [f(tau)]G1.
	Commitment stdkzg.Commitment[sw_bn254.G1Affine]

	// Opening proof containing:
	//
	//   Quotient     = pi
	//   ClaimedValue = y
	OpeningProof stdkzg.OpeningProof[
		sw_bn254.ScalarField,
		sw_bn254.G1Affine,
	]

	// Evaluation point z.
	Point emulated.Element[sw_bn254.ScalarField]
}

// Define specifies the circuit constraints.
func (c *KZGOpeningCircuit) Define(
	api frontend.API,
) error {

	// Create the generic KZG verifier using the
	// BN254 emulated curve implementation.
	verifier, err :=
		stdkzg.NewVerifier[
			sw_bn254.ScalarField,
			sw_bn254.G1Affine,
			sw_bn254.G2Affine,
			sw_bn254.GTEl,
		](api)

	if err != nil {
		return fmt.Errorf(
			"failed to create in-circuit KZG verifier: %w",
			err,
		)
	}

	// Enforce validity of:
	//
	//     commitment C
	//     opening proof pi
	//     evaluation point z
	//     claimed value y
	//     node-specific verifying key
	//
	// Conceptually this checks:
	//
	//     e(C - yG1, G2)
	//         =
	//     e(pi, [tau]G2 - zG2)
	if err :=
		verifier.CheckOpeningProof(
			c.Commitment,
			c.OpeningProof,
			c.Point,
			c.VerifyingKey,
		); err != nil {

		return fmt.Errorf(
			"in-circuit KZG opening verification failed: %w",
			err,
		)
	}

	return nil
}
