package snark

import (
	"fmt"

	"bplustree/bptree"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdkzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

// ============================================================
// BUILD REAL MEMBERSHIP CIRCUIT WITNESS
// ============================================================
//
// MembershipPathData already contains the real:
//
//   - search key
//   - leaf commitment
//   - leaf mapped value
//   - leaf opening
//   - leaf verification key
//   - internal separator relations
//   - internal commitments
//   - internal openings
//   - internal verification keys
//   - root commitment
//
// This function converts those native gnark-crypto objects into
// values usable by the gnark circuit.
func NewMembershipCircuitWitness(
	path *bptree.MembershipPathData[int],
) (*MembershipCircuit, error) {

	if path == nil {
		return nil, fmt.Errorf(
			"membership path is nil",
		)
	}

	// ============================================================
	// ROOT COMMITMENT
	// ============================================================

	rootCommitment, err :=
		stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
			path.RootCommitment,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"convert root commitment: %w",
			err,
		)
	}

	// ============================================================
	// LEAF COMMITMENT
	// ============================================================

	leafCommitment, err :=
		stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
			path.LeafCommitment,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"convert leaf commitment: %w",
			err,
		)
	}

	// ============================================================
	// LEAF OPENING PROOF
	// ============================================================

	leafOpeningProof, err :=
		stdkzg.ValueOfOpeningProof[
			sw_bn254.ScalarField,
			sw_bn254.G1Affine,
		](
			path.LeafOpeningProof,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"convert leaf opening proof: %w",
			err,
		)
	}

	// ============================================================
	// LEAF KZG VERIFICATION KEY
	// ============================================================

	leafVK, err :=
		stdkzg.ValueOfVerifyingKey[
			sw_bn254.G1Affine,
			sw_bn254.G2Affine,
		](
			path.LeafVerifyingKey,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"convert leaf verifying key: %w",
			err,
		)
	}

	// ============================================================
	// CREATE ASSIGNMENT
	// ============================================================

	assignment :=
		&MembershipCircuit{
			// ----------------------------------------------------
			// PUBLIC INPUTS
			// ----------------------------------------------------

			Key: path.Key,

			RootCommitment: rootCommitment,

			LeafVerifyingKey: leafVK,

			// ----------------------------------------------------
			// PRIVATE LEAF WITNESS
			// ----------------------------------------------------

			LeafMappedValue: emulated.ValueOf[sw_bn254.ScalarField](
				path.LeafMappedValue,
			),

			LeafEvaluationPoint: path.LeafEvaluationPoint,

			LeafCommitment: leafCommitment,

			LeafOpeningProof: leafOpeningProof,

			// ----------------------------------------------------
			// INTERNAL PATH
			// ----------------------------------------------------

			Levels: make(
				[]MembershipLevelCircuit,
				len(path.Levels),
			),

			// ----------------------------------------------------
			// STATIC CIRCUIT STRUCTURE
			// ----------------------------------------------------

			leafEvaluationPoint: path.LeafEvaluationPoint,
		}

	// ============================================================
	// INTERNAL LEVELS
	// ============================================================

	for levelIndex := range path.Levels {

		nativeLevel :=
			&path.Levels[levelIndex]

		circuitLevel :=
			&assignment.Levels[levelIndex]

		// ========================================================
		// PARENT COMMITMENT
		// ========================================================

		parentCommitment, err :=
			stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
				nativeLevel.ParentCommitment,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"level %d parent commitment: %w",
				levelIndex,
				err,
			)
		}

		circuitLevel.ParentCommitment =
			parentCommitment

		// ========================================================
		// PARENT VERIFICATION KEY
		// ========================================================

		parentVK, err :=
			stdkzg.ValueOfVerifyingKey[
				sw_bn254.G1Affine,
				sw_bn254.G2Affine,
			](
				nativeLevel.VerifyingKey,
			)

		if err != nil {
			return nil, fmt.Errorf(
				"level %d verifying key: %w",
				levelIndex,
				err,
			)
		}

		circuitLevel.VerifyingKey =
			parentVK

		// ========================================================
		// LOWER RELATION
		// ========================================================

		if nativeLevel.LowerRelation != nil {

			nativeLower :=
				nativeLevel.LowerRelation

			circuitLevel.hasLower =
				true

			// ----------------------------------------------------
			// Separator key
			// ----------------------------------------------------

			circuitLevel.Lower.SeparatorKey =
				nativeLower.SeparatorKey

			// ----------------------------------------------------
			// Evaluation point
			//
			// EvaluationPoint:
			//     actual private witness
			//
			// evaluationPoint:
			//     static expected value used by Define()
			// ----------------------------------------------------

			circuitLevel.Lower.EvaluationPoint =
				nativeLower.EvaluationPoint

			circuitLevel.Lower.evaluationPoint =
				nativeLower.EvaluationPoint

			// ----------------------------------------------------
			// Mapped value
			// ----------------------------------------------------

			circuitLevel.Lower.MappedValue =
				emulated.ValueOf[sw_bn254.ScalarField](
					nativeLower.MappedValue,
				)

			// ----------------------------------------------------
			// LEFT CHILD COMMITMENT
			// ----------------------------------------------------

			lpc, err :=
				stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
					nativeLower.LPC,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d lower LPC: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Lower.LPC =
				lpc

			// ----------------------------------------------------
			// RIGHT CHILD COMMITMENT
			// ----------------------------------------------------

			rpc, err :=
				stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
					nativeLower.RPC,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d lower RPC: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Lower.RPC =
				rpc

			// ----------------------------------------------------
			// KZG OPENING PROOF
			// ----------------------------------------------------

			openingProof, err :=
				stdkzg.ValueOfOpeningProof[
					sw_bn254.ScalarField,
					sw_bn254.G1Affine,
				](
					nativeLower.OpeningProof,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d lower opening proof: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Lower.OpeningProof =
				openingProof
		}

		// ========================================================
		// UPPER RELATION
		// ========================================================

		if nativeLevel.UpperRelation != nil {

			nativeUpper :=
				nativeLevel.UpperRelation

			circuitLevel.hasUpper =
				true

			// ----------------------------------------------------
			// Separator key
			// ----------------------------------------------------

			circuitLevel.Upper.SeparatorKey =
				nativeUpper.SeparatorKey

			// ----------------------------------------------------
			// Evaluation point
			// ----------------------------------------------------

			circuitLevel.Upper.EvaluationPoint =
				nativeUpper.EvaluationPoint

			circuitLevel.Upper.evaluationPoint =
				nativeUpper.EvaluationPoint

			// ----------------------------------------------------
			// Mapped value
			// ----------------------------------------------------

			circuitLevel.Upper.MappedValue =
				emulated.ValueOf[sw_bn254.ScalarField](
					nativeUpper.MappedValue,
				)

			// ----------------------------------------------------
			// LEFT CHILD COMMITMENT
			// ----------------------------------------------------

			lpc, err :=
				stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
					nativeUpper.LPC,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d upper LPC: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Upper.LPC =
				lpc

			// ----------------------------------------------------
			// RIGHT CHILD COMMITMENT
			// ----------------------------------------------------

			rpc, err :=
				stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
					nativeUpper.RPC,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d upper RPC: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Upper.RPC =
				rpc

			// ----------------------------------------------------
			// KZG OPENING PROOF
			// ----------------------------------------------------

			openingProof, err :=
				stdkzg.ValueOfOpeningProof[
					sw_bn254.ScalarField,
					sw_bn254.G1Affine,
				](
					nativeUpper.OpeningProof,
				)

			if err != nil {
				return nil, fmt.Errorf(
					"level %d upper opening proof: %w",
					levelIndex,
					err,
				)
			}

			circuitLevel.Upper.OpeningProof =
				openingProof
		}

		// ========================================================
		// FILL INACTIVE RELATION WITH DUMMY WITNESS DATA
		// ========================================================
		//
		// MembershipLevelCircuit always physically contains BOTH:
		//
		//     Lower MembershipSeparatorCircuit
		//     Upper MembershipSeparatorCircuit
		//
		// even though only one of them may participate in the
		// circuit for an edge child.
		//
		// frontend.NewWitness() still walks every exported field in
		// both structs. Therefore an inactive relation cannot contain
		// nil frontend.Variable / emulated values.
		//
		// The inactive relation is NOT constrained in Define() because
		// hasLower / hasUpper are compile-time booleans.
		//
		// Therefore we safely populate the inactive relation by copying
		// the active relation.
		//
		// This changes no circuit semantics.

		if !circuitLevel.hasLower &&
			circuitLevel.hasUpper {

			circuitLevel.Lower =
				circuitLevel.Upper
		}

		if !circuitLevel.hasUpper &&
			circuitLevel.hasLower {

			circuitLevel.Upper =
				circuitLevel.Lower
		}

		// ========================================================
		// SANITY CHECK
		// ========================================================

		if !circuitLevel.hasLower &&
			!circuitLevel.hasUpper {

			return nil, fmt.Errorf(
				"level %d has neither lower nor upper relation",
				levelIndex,
			)
		}
	}

	return assignment, nil
}
