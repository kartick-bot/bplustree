package snark

import (
	"fmt"

	"bplustree/bptree"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdkzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

// ============================================================
// CONVERT ONE NATIVE SEPARATOR RELATION
// ============================================================

func fillMembershipRelation(
	dst *MembershipSeparatorCircuit,
	src *bptree.MembershipSeparatorProof[int],
	levelIndex int,
) error {

	if src == nil {
		return fmt.Errorf(
			"level %d relation is nil",
			levelIndex,
		)
	}

	if src.MappedValue == nil {
		return fmt.Errorf(
			"level %d mapped value is nil",
			levelIndex,
		)
	}

	dst.SeparatorKey =
		src.SeparatorKey

	dst.EvaluationPoint =
		src.EvaluationPoint

	dst.MappedValue =
		emulated.ValueOf[sw_bn254.ScalarField](
			src.MappedValue,
		)

	// ========================================================
	// LPC
	// ========================================================

	lpc, err :=
		stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
			src.LPC,
		)

	if err != nil {
		return fmt.Errorf(
			"level %d LPC: %w",
			levelIndex,
			err,
		)
	}

	dst.LPC =
		lpc

	// ========================================================
	// RPC
	// ========================================================

	rpc, err :=
		stdkzg.ValueOfCommitment[sw_bn254.G1Affine](
			src.RPC,
		)

	if err != nil {
		return fmt.Errorf(
			"level %d RPC: %w",
			levelIndex,
			err,
		)
	}

	dst.RPC =
		rpc

	// ========================================================
	// OPENING PROOF
	// ========================================================

	openingProof, err :=
		stdkzg.ValueOfOpeningProof[
			sw_bn254.ScalarField,
			sw_bn254.G1Affine,
		](
			src.OpeningProof,
		)

	if err != nil {
		return fmt.Errorf(
			"level %d opening proof: %w",
			levelIndex,
			err,
		)
	}

	dst.OpeningProof =
		openingProof

	return nil
}

// ============================================================
// BUILD WITNESS FOR ANY KEY
// ============================================================
//
// IMPORTANT:
//
// The resulting witness may differ for every key.
//
// The circuit does NOT.
//
// For every internal level:
//
//	LowerRelation:
//	    IsLPC = 0
//	    use the lower separator
//	    current child = RPC
//
//	UpperRelation:
//	    IsLPC = 1
//	    use the upper separator
//	    current child = LPC
//
// Exactly ONE relation must be present at each level.
func NewMembershipCircuitWitness(
	path *bptree.MembershipPathData[int],
) (*MembershipCircuit, error) {

	if path == nil {
		return nil, fmt.Errorf(
			"membership path is nil",
		)
	}

	if len(path.Levels) == 0 {
		return nil, fmt.Errorf(
			"membership path has no internal levels",
		)
	}

	if path.LeafMappedValue == nil {
		return nil, fmt.Errorf(
			"leaf mapped value is nil",
		)
	}

	// ========================================================
	// ROOT COMMITMENT
	// ========================================================

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

	// ========================================================
	// LEAF COMMITMENT
	// ========================================================

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

	// ========================================================
	// LEAF OPENING
	// ========================================================

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

	// ========================================================
	// LEAF VERIFICATION KEY
	// ========================================================

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

	// ========================================================
	// CREATE ASSIGNMENT
	// ========================================================

	assignment :=
		&MembershipCircuit{

			Key: path.Key,

			RootCommitment: rootCommitment,

			LeafMappedValue: emulated.ValueOf[sw_bn254.ScalarField](
				path.LeafMappedValue,
			),

			LeafEvaluationPoint: path.LeafEvaluationPoint,

			LeafCommitment: leafCommitment,

			LeafOpeningProof: leafOpeningProof,

			LeafVerifyingKey: leafVK,

			Levels: make(
				[]MembershipLevelCircuit,
				len(path.Levels),
			),
		}

	// ========================================================
	// INTERNAL LEVELS
	// ========================================================

	for levelIndex := range path.Levels {

		nativeLevel :=
			&path.Levels[levelIndex]

		circuitLevel :=
			&assignment.Levels[levelIndex]

		// ====================================================
		// PARENT COMMITMENT
		// ====================================================

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

		// ====================================================
		// PARENT VERIFICATION KEY
		// ====================================================

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

		// ====================================================
		// CHOOSE THE ONE AUTHENTICATED RELATION
		// ====================================================

		var relation *bptree.MembershipSeparatorProof[int]

		switch {

		// ----------------------------------------------------
		// LOWER / RPC
		// ----------------------------------------------------

		case nativeLevel.LowerRelation != nil &&
			nativeLevel.UpperRelation == nil:

			circuitLevel.IsLPC =
				0

			relation =
				nativeLevel.LowerRelation

		// ----------------------------------------------------
		// UPPER / LPC
		// ----------------------------------------------------

		case nativeLevel.UpperRelation != nil &&
			nativeLevel.LowerRelation == nil:

			circuitLevel.IsLPC =
				1

			relation =
				nativeLevel.UpperRelation

		// ----------------------------------------------------
		// INVALID: NONE
		// ----------------------------------------------------

		case nativeLevel.LowerRelation == nil &&
			nativeLevel.UpperRelation == nil:

			return nil, fmt.Errorf(
				"level %d has no separator relation",
				levelIndex,
			)

		// ----------------------------------------------------
		// INVALID: BOTH
		// ----------------------------------------------------

		default:

			return nil, fmt.Errorf(
				"level %d has both lower and upper relations; universal one-opening circuit requires exactly one",
				levelIndex,
			)
		}

		// ====================================================
		// COPY THE SELECTED RELATION INTO THE SINGLE CIRCUIT
		// SLOT
		// ====================================================

		if err :=
			fillMembershipRelation(
				&circuitLevel.Relation,
				relation,
				levelIndex,
			); err != nil {

			return nil, err
		}
	}

	return assignment, nil
}
