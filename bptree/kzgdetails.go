package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// PrintKZGDetails prints detailed KZG information
// for every leaf.
//
// Each leaf has:
//
//   - its own entries
//   - global evaluation points
//   - mapped field values
//   - interpolating polynomial
//   - independently generated SRS
//   - one final KZG commitment
//   - opening proofs
//   - pairing verification
func (t *Tree[K, V]) PrintKZGDetails() error {

	if t.root == nil {
		return fmt.Errorf(
			"tree has no root",
		)
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("LEAF KZG DETAILS")
	fmt.Println("================================================================")

	fmt.Println()
	fmt.Println("BN254 scalar-field modulus p:")
	fmt.Println(t.modulus.String())

	leafNumber := 0

	// Special case:
	// the complete tree consists of one leaf.
	if t.root.isLeaf {

		return t.printSingleLeafKZGDetails(
			t.root,
			nil,
			-1,
			&leafNumber,
		)
	}

	return t.printKZGDetailsRecursive(
		t.root,
		&leafNumber,
	)
}

// printKZGDetailsRecursive traverses the tree from left to right
// and prints information for every leaf.
func (t *Tree[K, V]) printKZGDetailsRecursive(
	parent *node[K, V],
	leafNumber *int,
) error {

	if parent == nil ||
		parent.isLeaf {

		return nil
	}

	for childIndex, child := range parent.children {

		if child == nil {

			return fmt.Errorf(
				"nil child at index %d",
				childIndex,
			)
		}

		if child.isLeaf {

			if err :=
				t.printSingleLeafKZGDetails(
					child,
					parent,
					childIndex,
					leafNumber,
				); err != nil {

				return err
			}

			continue
		}

		if err :=
			t.printKZGDetailsRecursive(
				child,
				leafNumber,
			); err != nil {

			return err
		}
	}

	return nil
}

// printSingleLeafKZGDetails prints all KZG information
// for one leaf.
func (t *Tree[K, V]) printSingleLeafKZGDetails(
	leaf *node[K, V],
	parent *node[K, V],
	childIndex int,
	leafNumber *int,
) error {

	if leaf == nil {

		return fmt.Errorf(
			"nil leaf encountered",
		)
	}

	if !leaf.isLeaf {

		return fmt.Errorf(
			"printSingleLeafKZGDetails called on internal node",
		)
	}

	if len(leaf.entries) == 0 {

		return fmt.Errorf(
			"cannot print KZG details for empty leaf",
		)
	}

	if len(leaf.entries) !=
		len(leaf.mappedValues) {

		return fmt.Errorf(
			"leaf %d entry/mapped-value length mismatch",
			*leafNumber,
		)
	}

	if len(leaf.entries) !=
		len(leaf.evaluationPoints) {

		return fmt.Errorf(
			"leaf %d has %d entries but %d evaluation points",
			*leafNumber,
			len(leaf.entries),
			len(leaf.evaluationPoints),
		)
	}

	if leaf.nodeSRS == nil {

		return fmt.Errorf(
			"leaf %d has no KZG SRS",
			*leafNumber,
		)
	}

	if leaf.commitment == nil {

		return fmt.Errorf(
			"leaf %d has no KZG commitment",
			*leafNumber,
		)
	}

	// ============================================================
	// LEAF HEADER
	// ============================================================

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Printf("LEAF %d\n", *leafNumber)
	fmt.Println("================================================================")

	// ============================================================
	// LEAF ENTRIES
	// ============================================================

	fmt.Println()
	fmt.Println("Leaf entries:")

	for i, entry := range leaf.entries {

		fmt.Printf(
			"  entry[%d]: key = %v\n",
			i,
			entry.Key,
		)
	}

	// ============================================================
	// GLOBAL EVALUATION POINTS + MAPPED VALUES
	// ============================================================

	fmt.Println()
	fmt.Println("Global evaluation points and mapped values:")

	for i, entry := range leaf.entries {

		fmt.Printf(
			"\n  Element %d\n",
			i,
		)

		fmt.Printf(
			"    key                = %v\n",
			entry.Key,
		)

		fmt.Printf(
			"    H(key)             = %x\n",
			entry.Value,
		)

		fmt.Printf(
			"    global point z_%d  = %d\n",
			i,
			leaf.evaluationPoints[i],
		)

		fmt.Printf(
			"    mapped value m_%d  = %s\n",
			i,
			leaf.mappedValues[i].String(),
		)
	}

	// ============================================================
	// RECONSTRUCT THE EXACT LEAF POLYNOMIAL
	//
	// IMPORTANT:
	//
	// Leaves use GLOBAL evaluation points.
	//
	//     f(z_i) = m_i
	//
	// where z_i is the global slot assigned to the entry.
	// ============================================================

	coefficients, err :=
		interpolateAtPoints(
			leaf.evaluationPoints,
			leaf.mappedValues,
			t.modulus,
		)

	if err != nil {

		return fmt.Errorf(
			"failed to reconstruct polynomial for leaf %d: %w",
			*leafNumber,
			err,
		)
	}

	// ============================================================
	// POLYNOMIAL: EVALUATION FORM
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("INTERPOLATING POLYNOMIAL")
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"Degree <= %d\n",
		len(coefficients)-1,
	)

	fmt.Println()
	fmt.Println("Evaluation form:")

	for i := range leaf.mappedValues {

		fmt.Printf(
			"  f_%d(%d) = %s\n",
			*leafNumber,
			leaf.evaluationPoints[i],
			leaf.mappedValues[i].String(),
		)
	}

	// ============================================================
	// POLYNOMIAL: COEFFICIENT FORM
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient form:")

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		fmt.Printf(
			"  a_%d = %s\n",
			i,
			coefficientBig.String(),
		)

		fmt.Printf(
			"        0x%s\n",
			coefficientBig.Text(16),
		)
	}

	fmt.Println()

	fmt.Printf(
		"f_%d(X) = ",
		*leafNumber,
	)

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		if i > 0 {
			fmt.Print(" + ")
		}

		switch i {

		case 0:

			fmt.Printf(
				"%s",
				coefficientBig.String(),
			)

		case 1:

			fmt.Printf(
				"%s X",
				coefficientBig.String(),
			)

		default:

			fmt.Printf(
				"%s X^%d",
				coefficientBig.String(),
				i,
			)
		}
	}

	fmt.Println()

	// ============================================================
	// VERIFY THAT THE POLYNOMIAL EVALUATES CORRECTLY
	// ============================================================

	fmt.Println()
	fmt.Println("Polynomial evaluation checks:")

	for i := range leaf.evaluationPoints {

		var x fr.Element

		x.SetUint64(
			leaf.evaluationPoints[i],
		)

		evaluated :=
			evaluatePolynomial(
				coefficients,
				x,
			)

		var evaluatedBig big.Int

		evaluated.BigInt(
			&evaluatedBig,
		)

		expected :=
			leaf.mappedValues[i]

		match :=
			evaluatedBig.Cmp(
				expected,
			) == 0

		fmt.Printf(
			"  f_%d(%d) = %s, expected = %s, match = %v\n",
			*leafNumber,
			leaf.evaluationPoints[i],
			evaluatedBig.String(),
			expected.String(),
			match,
		)
	}

	// ============================================================
	// LEAF SRS
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("SRS FOR LEAF %d\n", *leafNumber)
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"Number of G1 proving-key powers: %d\n",
		len(leaf.nodeSRS.Pk.G1),
	)

	fmt.Println()
	fmt.Println("Proving-key G1 powers:")

	for i := range leaf.nodeSRS.Pk.G1 {

		b :=
			leaf.nodeSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  SRS_leaf_%d[%d] = [tau_%d^%d]G1\n",
			*leafNumber,
			i,
			*leafNumber,
			i,
		)

		fmt.Printf(
			"    compressed = %x\n",
			b,
		)
	}

	fmt.Println()
	fmt.Println("Verifying-key G1:")

	vkG1 :=
		leaf.nodeSRS.Vk.G1.Bytes()

	fmt.Printf(
		"  %x\n",
		vkG1,
	)

	fmt.Println()
	fmt.Println("Verifying-key G2 points:")

	for i := range leaf.nodeSRS.Vk.G2 {

		b :=
			leaf.nodeSRS.Vk.G2[i].Bytes()

		fmt.Printf(
			"  VK.G2[%d] = %x\n",
			i,
			b,
		)
	}

	fmt.Println()

	fmt.Printf(
		"Leaf %d uses its own independently generated trapdoor tau_%d.\n",
		*leafNumber,
		*leafNumber,
	)

	fmt.Println(
		"The secret trapdoor itself is not stored or printed.",
	)

	// ============================================================
	// SRS POWERS USED BY THE POLYNOMIAL
	// ============================================================

	if len(coefficients) >
		len(leaf.nodeSRS.Pk.G1) {

		return fmt.Errorf(
			"leaf %d requires %d SRS powers but its SRS has only %d",
			*leafNumber,
			len(coefficients),
			len(leaf.nodeSRS.Pk.G1),
		)
	}

	fmt.Println()
	fmt.Println("SRS powers used by this polynomial:")

	for i := range coefficients {

		srsBytes :=
			leaf.nodeSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  [tau_%d^%d]G1 = %x\n",
			*leafNumber,
			i,
			srsBytes,
		)
	}

	// ============================================================
	// COEFFICIENT CONTRIBUTIONS
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient KZG contributions:")

	fmt.Printf(
		"  C_leaf_%d = sum_i a_i [tau_%d^i]G1\n",
		*leafNumber,
		*leafNumber,
	)

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		var contribution kzg.Digest

		contribution.ScalarMultiplication(
			&leaf.nodeSRS.Pk.G1[i],
			&coefficientBig,
		)

		contributionBytes :=
			contribution.Bytes()

		fmt.Printf(
			"  a_%d * [tau_%d^%d]G1 = %x\n",
			i,
			*leafNumber,
			i,
			contributionBytes,
		)
	}

	// ============================================================
	// RECOMPUTE FINAL LEAF COMMITMENT
	// ============================================================

	recomputedCommitment, err :=
		kzg.Commit(
			coefficients,
			leaf.nodeSRS.Pk,
		)

	if err != nil {

		return fmt.Errorf(
			"failed to recompute leaf %d commitment: %w",
			*leafNumber,
			err,
		)
	}

	recomputedBytes :=
		recomputedCommitment.Bytes()

	storedBytes :=
		leaf.commitment.Bytes()

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("FINAL LEAF KZG COMMITMENT")
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"  recomputed C_leaf_%d = %x\n",
		*leafNumber,
		recomputedBytes,
	)

	fmt.Printf(
		"  stored     C_leaf_%d = %x\n",
		*leafNumber,
		storedBytes,
	)

	commitmentMatches :=
		leaf.commitment.Equal(
			&recomputedCommitment,
		)

	fmt.Printf(
		"  stored == recomputed = %v\n",
		commitmentMatches,
	)

	// ============================================================
	// OPENING PROOFS AND PAIRING VERIFICATION
	// ============================================================

	if len(leaf.openingProofs) !=
		len(leaf.mappedValues) {

		return fmt.Errorf(
			"leaf %d has %d mapped values but %d opening proofs",
			*leafNumber,
			len(leaf.mappedValues),
			len(leaf.openingProofs),
		)
	}

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("KZG OPENING PROOFS AND PAIRING VERIFICATION")
	fmt.Println("----------------------------------------------------------------")

	for i := range leaf.openingProofs {

		proof :=
			&leaf.openingProofs[i]

		evaluationPoint :=
			leaf.evaluationPoints[i]

		// Convert the global evaluation point into
		// a BN254 scalar-field element.
		var point fr.Element

		point.SetUint64(
			evaluationPoint,
		)

		// Expected mapped value.
		var expectedElement fr.Element

		expectedElement.SetBigInt(
			leaf.mappedValues[i],
		)

		// Claimed value contained in the opening proof.
		var claimedBig big.Int

		proof.ClaimedValue.BigInt(
			&claimedBig,
		)

		claimedMatches :=
			proof.ClaimedValue.Equal(
				&expectedElement,
			)

		proofBytes :=
			proof.H.Bytes()

		fmt.Println()
		fmt.Println("............................................................")

		fmt.Printf(
			"OPENING %d\n",
			i,
		)

		fmt.Println("............................................................")

		fmt.Printf(
			"  key                        = %v\n",
			leaf.entries[i].Key,
		)

		fmt.Printf(
			"  global evaluation point z = %d\n",
			evaluationPoint,
		)

		fmt.Printf(
			"  expected mapped value y    = %s\n",
			leaf.mappedValues[i].String(),
		)

		fmt.Printf(
			"  proof claimed value        = %s\n",
			claimedBig.String(),
		)

		fmt.Printf(
			"  claimed value == expected  = %v\n",
			claimedMatches,
		)

		fmt.Printf(
			"  opening proof pi            = %x\n",
			proofBytes,
		)

		// ========================================================
		// PAIRING EQUATION
		// ========================================================

		fmt.Println()
		fmt.Println("  KZG pairing equation:")
		fmt.Println()

		fmt.Println(
			"    e(C - yG1, G2)",
		)

		fmt.Println(
			"           =",
		)

		fmt.Println(
			"    e(pi, [tau]G2 - zG2)",
		)

		fmt.Println()

		fmt.Printf(
			"    z  = %d\n",
			evaluationPoint,
		)

		fmt.Printf(
			"    y  = %s\n",
			leaf.mappedValues[i].String(),
		)

		fmt.Printf(
			"    C  = %x\n",
			storedBytes,
		)

		fmt.Printf(
			"    pi = %x\n",
			proofBytes,
		)

		// ========================================================
		// VERIFICATION KEY
		// ========================================================

		fmt.Println()
		fmt.Println("  Verification-key G2 elements:")

		for j := range leaf.nodeSRS.Vk.G2 {

			g2Bytes :=
				leaf.nodeSRS.Vk.G2[j].Bytes()

			fmt.Printf(
				"    VK.G2[%d] = %x\n",
				j,
				g2Bytes,
			)
		}

		// ========================================================
		// ACTUAL PAIRING VERIFICATION
		// ========================================================

		verifyErr :=
			kzg.Verify(
				leaf.commitment,
				proof,
				point,
				leaf.nodeSRS.Vk,
			)

		fmt.Println()
		fmt.Print(
			"  Pairing verification: ",
		)

		if verifyErr != nil {

			fmt.Println(
				"FAILED",
			)

			return fmt.Errorf(
				"leaf %d opening %d failed KZG pairing verification at global evaluation point %d: %w",
				*leafNumber,
				i,
				evaluationPoint,
				verifyErr,
			)
		}

		fmt.Println(
			"PASSED",
		)
	}

	fmt.Println()
	fmt.Printf(
		"Leaf %d: all %d KZG opening pairings PASSED\n",
		*leafNumber,
		len(leaf.openingProofs),
	)

	// ============================================================
	// PARENT LPC / RPC INTERPRETATION
	// ============================================================

	if parent != nil {

		fmt.Println()
		fmt.Println("----------------------------------------------------------------")
		fmt.Println("PARENT LPC / RPC INTERPRETATION")
		fmt.Println("----------------------------------------------------------------")

		fmt.Printf(
			"child index = %d\n",
			childIndex,
		)

		if childIndex <
			len(parent.keys) {

			fmt.Printf(
				"  This commitment is LPC[%d] for separator key %v\n",
				childIndex,
				parent.keys[childIndex],
			)
		}

		if childIndex > 0 {

			fmt.Printf(
				"  This commitment is RPC[%d] for separator key %v\n",
				childIndex-1,
				parent.keys[childIndex-1],
			)
		}

		if childIndex <
			len(parent.childCommitments) &&
			parent.childCommitments[childIndex] != nil {

			storedParent :=
				parent.childCommitments[childIndex]

			storedParentBytes :=
				storedParent.Bytes()

			fmt.Printf(
				"  parent-stored commitment = %x\n",
				storedParentBytes,
			)

			equal :=
				storedParent.Equal(
					&recomputedCommitment,
				)

			fmt.Printf(
				"  parent stored == leaf commitment = %v\n",
				equal,
			)

		} else {

			fmt.Println(
				"  parent-stored commitment = <missing>",
			)
		}
	}

	// ============================================================
	// COMPLETE LEAF
	// ============================================================

	fmt.Println()
	fmt.Println("================================================================")

	fmt.Printf(
		"END LEAF %d\n",
		*leafNumber,
	)

	fmt.Println("================================================================")

	*leafNumber =
		*leafNumber + 1

	return nil
}

// evaluatePolynomial evaluates:
//
//	f(X) = a_0 + a_1 X + ... + a_n X^n
//
// using Horner's rule.
func evaluatePolynomial(
	coefficients []fr.Element,
	x fr.Element,
) fr.Element {

	var result fr.Element

	result.SetZero()

	for i :=
		len(coefficients) - 1; i >= 0; i-- {

		result.Mul(
			&result,
			&x,
		)

		result.Add(
			&result,
			&coefficients[i],
		)
	}

	return result
}
