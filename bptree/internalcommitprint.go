package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// PrintInternalCommitmentDetails prints the recursive
// KZG information for every internal node, including the root.
//
// BuildCommitments() must be called before this function.
func (t *Tree[K, V]) PrintInternalCommitmentDetails() error {

	if t.root == nil {

		return fmt.Errorf(
			"tree has no root",
		)
	}

	if t.root.isLeaf {

		fmt.Println(
			"Tree contains only one leaf; there are no internal nodes.",
		)

		return nil
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Println("RECURSIVE INTERNAL-NODE KZG DETAILS")
	fmt.Println("================================================================")

	internalNumber := 0

	return t.printInternalNodeRecursive(
		t.root,
		&internalNumber,
	)
}

// printInternalNodeRecursive prints internal nodes recursively.
//
// We recurse into internal children first so that the output
// follows the bottom-up commitment construction:
//
//	leaves
//	  ↓
//	lower internal nodes
//	  ↓
//	root
func (t *Tree[K, V]) printInternalNodeRecursive(
	n *node[K, V],
	internalNumber *int,
) error {

	if n == nil {

		return fmt.Errorf(
			"nil node encountered",
		)
	}

	if n.isLeaf {

		return nil
	}

	// ============================================================
	// FIRST PRINT LOWER INTERNAL NODES
	// ============================================================

	for _, child := range n.children {

		if child != nil &&
			!child.isLeaf {

			if err :=
				t.printInternalNodeRecursive(
					child,
					internalNumber,
				); err != nil {

				return err
			}
		}
	}

	// ============================================================
	// NOW PRINT THIS INTERNAL NODE
	// ============================================================

	isRoot :=
		n == t.root

	fmt.Println()
	fmt.Println("================================================================")

	if isRoot {

		fmt.Println("ROOT NODE")

	} else {

		fmt.Printf(
			"INTERNAL NODE %d\n",
			*internalNumber,
		)
	}

	fmt.Println("================================================================")

	fmt.Println()

	fmt.Printf(
		"Keys: %v\n",
		n.keys,
	)

	// ============================================================
	// SANITY CHECKS
	// ============================================================

	if len(n.children) !=
		len(n.keys)+1 {

		return fmt.Errorf(
			"internal node has %d keys but %d children",
			len(n.keys),
			len(n.children),
		)
	}

	if len(n.childCommitments) !=
		len(n.children) {

		return fmt.Errorf(
			"internal node has %d children but %d child commitments",
			len(n.children),
			len(n.childCommitments),
		)
	}

	if len(n.internalMappedValues) !=
		len(n.keys) {

		return fmt.Errorf(
			"internal node has %d keys but %d mapped values",
			len(n.keys),
			len(n.internalMappedValues),
		)
	}

	if n.nodeSRS == nil {

		return fmt.Errorf(
			"internal node has no SRS",
		)
	}

	if n.commitment == nil {

		return fmt.Errorf(
			"internal node has no commitment",
		)
	}

	if len(n.openingProofs) !=
		len(n.internalMappedValues) {

		return fmt.Errorf(
			"internal node has %d mapped values but %d opening proofs",
			len(n.internalMappedValues),
			len(n.openingProofs),
		)
	}

	// ============================================================
	// PRINT EACH INTERNAL ENTRY
	// ============================================================

	fmt.Println()
	fmt.Println("Internal entries:")

	for i, key := range n.keys {

		lpc :=
			n.childCommitments[i]

		rpc :=
			n.childCommitments[i+1]

		if lpc == nil {

			return fmt.Errorf(
				"LPC[%d] is nil",
				i,
			)
		}

		if rpc == nil {

			return fmt.Errorf(
				"RPC[%d] is nil",
				i,
			)
		}

		if n.internalMappedValues[i] == nil {

			return fmt.Errorf(
				"mapped value %d is nil",
				i,
			)
		}

		lpcBytes :=
			lpc.Bytes()

		rpcBytes :=
			rpc.Bytes()

		fmt.Println()

		fmt.Printf(
			"  Entry %d\n",
			i,
		)

		fmt.Printf(
			"    key          = %v\n",
			key,
		)

		fmt.Printf(
			"    LPC[%d]       = %x\n",
			i,
			lpcBytes,
		)

		fmt.Printf(
			"    RPC[%d]       = %x\n",
			i,
			rpcBytes,
		)

		fmt.Printf(
			"    mapped m_%d   = %s\n",
			i,
			n.internalMappedValues[i].String(),
		)

		// --------------------------------------------------------
		// Shared child-pointer relationship:
		//
		// LPC[i] = RPC[i-1]
		// --------------------------------------------------------

		if i > 0 {

			previousRPC :=
				n.childCommitments[i]

			equal :=
				lpc.Equal(
					previousRPC,
				)

			fmt.Printf(
				"    LPC[%d] == RPC[%d] = %v\n",
				i,
				i-1,
				equal,
			)
		}
	}

	// ============================================================
	// BUILD FIELD-ELEMENT ARRAY
	// ============================================================

	values :=
		make(
			[]fr.Element,
			len(n.internalMappedValues),
		)

	for i, mapped := range n.internalMappedValues {

		values[i].SetBigInt(
			mapped,
		)
	}

	// ============================================================
	// INTERPOLATE INTERNAL-NODE POLYNOMIAL
	//
	// IMPORTANT:
	//
	// Internal nodes continue to use LOCAL evaluation points:
	//
	//     f(0) = m_0
	//     f(1) = m_1
	//     ...
	//
	// This is intentionally different from the leaves.
	// ============================================================

	poly :=
		polynomial.InterpolateOnRange(
			values,
		)

	coefficients :=
		[]fr.Element(poly)

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("INTERNAL-NODE POLYNOMIAL")
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"number of mapped values = %d\n",
		len(values),
	)

	fmt.Printf(
		"degree <= %d\n",
		len(coefficients)-1,
	)

	// ============================================================
	// EVALUATION FORM
	// ============================================================

	fmt.Println()
	fmt.Println("Evaluation form:")

	for i, mapped := range n.internalMappedValues {

		fmt.Printf(
			"  f(%d) = %s\n",
			i,
			mapped.String(),
		)
	}

	// ============================================================
	// COEFFICIENT FORM
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient form:")

	for i := range coefficients {

		var coefficient big.Int

		coefficients[i].BigInt(
			&coefficient,
		)

		fmt.Printf(
			"  a_%d = %s\n",
			i,
			coefficient.String(),
		)

		fmt.Printf(
			"        0x%s\n",
			coefficient.Text(16),
		)
	}

	fmt.Println()

	fmt.Print(
		"f(X) = ",
	)

	for i := range coefficients {

		var coefficient big.Int

		coefficients[i].BigInt(
			&coefficient,
		)

		if i > 0 {
			fmt.Print(" + ")
		}

		switch i {

		case 0:

			fmt.Printf(
				"%s",
				coefficient.String(),
			)

		case 1:

			fmt.Printf(
				"%s X",
				coefficient.String(),
			)

		default:

			fmt.Printf(
				"%s X^%d",
				coefficient.String(),
				i,
			)
		}
	}

	fmt.Println()

	// ============================================================
	// POLYNOMIAL EVALUATION CHECKS
	// ============================================================

	fmt.Println()
	fmt.Println("Polynomial evaluation checks:")

	for i := range n.internalMappedValues {

		var point fr.Element

		point.SetUint64(
			uint64(i),
		)

		evaluated :=
			evaluatePolynomial(
				coefficients,
				point,
			)

		var evaluatedBig big.Int

		evaluated.BigInt(
			&evaluatedBig,
		)

		expected :=
			n.internalMappedValues[i]

		match :=
			evaluatedBig.Cmp(
				expected,
			) == 0

		fmt.Printf(
			"  f(%d) = %s, expected = %s, match = %v\n",
			i,
			evaluatedBig.String(),
			expected.String(),
			match,
		)
	}

	// ============================================================
	// NODE-SPECIFIC SRS
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("NODE SRS")
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"Number of G1 proving-key powers = %d\n",
		len(n.nodeSRS.Pk.G1),
	)

	fmt.Println()
	fmt.Println("Proving-key G1 powers:")

	for i := range n.nodeSRS.Pk.G1 {

		srsBytes :=
			n.nodeSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  [tau^%d]G1 = %x\n",
			i,
			srsBytes,
		)
	}

	fmt.Println()
	fmt.Println("Verifying-key G1:")

	vkG1 :=
		n.nodeSRS.Vk.G1.Bytes()

	fmt.Printf(
		"  %x\n",
		vkG1,
	)

	fmt.Println()
	fmt.Println("Verifying-key G2 points:")

	for i := range n.nodeSRS.Vk.G2 {

		g2Bytes :=
			n.nodeSRS.Vk.G2[i].Bytes()

		fmt.Printf(
			"  VK.G2[%d] = %x\n",
			i,
			g2Bytes,
		)
	}

	fmt.Println()
	fmt.Println(
		"This internal node uses its own independently generated trapdoor tau.",
	)

	fmt.Println(
		"The secret trapdoor itself is not stored or printed.",
	)

	// ============================================================
	// SRS POWERS USED BY THIS POLYNOMIAL
	// ============================================================

	if len(coefficients) >
		len(n.nodeSRS.Pk.G1) {

		return fmt.Errorf(
			"internal node requires %d SRS powers but has only %d",
			len(coefficients),
			len(n.nodeSRS.Pk.G1),
		)
	}

	fmt.Println()
	fmt.Println("SRS powers used by this polynomial:")

	for i := range coefficients {

		srsBytes :=
			n.nodeSRS.Pk.G1[i].Bytes()

		fmt.Printf(
			"  [tau^%d]G1 = %x\n",
			i,
			srsBytes,
		)
	}

	// ============================================================
	// COEFFICIENT KZG CONTRIBUTIONS
	// ============================================================

	fmt.Println()
	fmt.Println("Coefficient KZG contributions:")

	fmt.Println(
		"  C_node = sum_i a_i [tau^i]G1",
	)

	for i := range coefficients {

		var coefficientBig big.Int

		coefficients[i].BigInt(
			&coefficientBig,
		)

		var contribution kzg.Digest

		contribution.ScalarMultiplication(
			&n.nodeSRS.Pk.G1[i],
			&coefficientBig,
		)

		contributionBytes :=
			contribution.Bytes()

		fmt.Printf(
			"  a_%d * [tau^%d]G1 = %x\n",
			i,
			i,
			contributionBytes,
		)
	}

	// ============================================================
	// RECOMPUTE FINAL NODE COMMITMENT
	// ============================================================

	recomputedCommitment, err :=
		kzg.Commit(
			coefficients,
			n.nodeSRS.Pk,
		)

	if err != nil {

		return fmt.Errorf(
			"failed to recompute internal-node commitment: %w",
			err,
		)
	}

	recomputedBytes :=
		recomputedCommitment.Bytes()

	commitmentBytes :=
		n.commitment.Bytes()

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("FINAL NODE KZG COMMITMENT")
	fmt.Println("----------------------------------------------------------------")

	fmt.Printf(
		"  recomputed C_node = %x\n",
		recomputedBytes,
	)

	fmt.Printf(
		"  stored     C_node = %x\n",
		commitmentBytes,
	)

	commitmentMatches :=
		n.commitment.Equal(
			&recomputedCommitment,
		)

	fmt.Printf(
		"  stored == recomputed = %v\n",
		commitmentMatches,
	)

	// ============================================================
	// INTERNAL-NODE OPENING PROOFS
	//
	// These use LOCAL evaluation points:
	//
	//     z = 0, 1, 2, ...
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("KZG OPENING PROOFS AND PAIRING VERIFICATION")
	fmt.Println("----------------------------------------------------------------")

	for i := range n.openingProofs {

		proof :=
			&n.openingProofs[i]

		// Internal nodes use the local point i.
		evaluationPoint :=
			uint64(i)

		var point fr.Element

		point.SetUint64(
			evaluationPoint,
		)

		// Expected mapped value.
		var expectedElement fr.Element

		expectedElement.SetBigInt(
			n.internalMappedValues[i],
		)

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
			"  separator key              = %v\n",
			n.keys[i],
		)

		fmt.Printf(
			"  local evaluation point z   = %d\n",
			evaluationPoint,
		)

		fmt.Printf(
			"  expected mapped value y    = %s\n",
			n.internalMappedValues[i].String(),
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
			n.internalMappedValues[i].String(),
		)

		fmt.Printf(
			"    C  = %x\n",
			commitmentBytes,
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

		for j := range n.nodeSRS.Vk.G2 {

			g2Bytes :=
				n.nodeSRS.Vk.G2[j].Bytes()

			fmt.Printf(
				"    VK.G2[%d] = %x\n",
				j,
				g2Bytes,
			)
		}

		// ========================================================
		// ACTUAL KZG PAIRING VERIFICATION
		// ========================================================

		verifyErr :=
			kzg.Verify(
				n.commitment,
				proof,
				point,
				n.nodeSRS.Vk,
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
				"internal-node opening %d failed KZG pairing verification at evaluation point %d: %w",
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

	if isRoot {

		fmt.Printf(
			"ROOT: all %d KZG opening pairings PASSED\n",
			len(n.openingProofs),
		)

	} else {

		fmt.Printf(
			"Internal node %d: all %d KZG opening pairings PASSED\n",
			*internalNumber,
			len(n.openingProofs),
		)
	}

	// ============================================================
	// EXPLAIN WHAT THE PARENT SEES
	// ============================================================

	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("PARENT COMMITMENT INTERPRETATION")
	fmt.Println("----------------------------------------------------------------")

	if isRoot {

		fmt.Println(
			"  This is the final recursive ROOT commitment.",
		)

	} else {

		fmt.Println(
			"  This commitment becomes one child commitment",
		)

		fmt.Println(
			"  (LPC or RPC) in the node's parent.",
		)
	}

	// ============================================================
	// END NODE
	// ============================================================

	fmt.Println()
	fmt.Println("================================================================")

	if isRoot {

		fmt.Println(
			"END ROOT NODE",
		)

	} else {

		fmt.Printf(
			"END INTERNAL NODE %d\n",
			*internalNumber,
		)
	}

	fmt.Println("================================================================")

	if !isRoot {

		*internalNumber =
			*internalNumber + 1
	}

	return nil
}
