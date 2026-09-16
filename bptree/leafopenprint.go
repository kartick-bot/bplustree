package bptree

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// PrintLeafOpeningProofs prints every KZG opening proof
// generated for every leaf.
//
// For every leaf entry it prints:
//
//   - key
//   - global evaluation point z
//   - expected mapped value
//   - claimed value contained in the proof
//   - opening proof pi
//   - leaf commitment C
//   - KZG pairing equation being checked
//   - verification result
//
// Leaf evaluation points are GLOBAL across the leaf layer.
//
// Example for order = 4:
//
//	Leaf 0 -> 0, 1, 2
//	Leaf 1 -> 3, 4, 5
//	Leaf 2 -> 6, 7, 8
//	...
func (t *Tree[K, V]) PrintLeafOpeningProofs() error {

	if t.root == nil {
		return fmt.Errorf(
			"tree has no root",
		)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LEAF KZG OPENING PROOFS AND PAIRING VERIFICATION")
	fmt.Println("============================================================")

	leafNumber := 0

	return t.printLeafOpeningProofsRecursive(
		t.root,
		&leafNumber,
	)
}

func (t *Tree[K, V]) printLeafOpeningProofsRecursive(
	n *node[K, V],
	leafNumber *int,
) error {

	if n == nil {
		return fmt.Errorf(
			"nil node encountered",
		)
	}

	// ============================================================
	// RECURSE UNTIL WE REACH A LEAF
	// ============================================================

	if !n.isLeaf {

		for _, child := range n.children {

			if err :=
				t.printLeafOpeningProofsRecursive(
					child,
					leafNumber,
				); err != nil {

				return err
			}
		}

		return nil
	}

	// ============================================================
	// BASIC CONSISTENCY CHECKS
	// ============================================================

	if len(n.entries) !=
		len(n.mappedValues) {

		return fmt.Errorf(
			"leaf %d has %d entries but %d mapped values",
			*leafNumber,
			len(n.entries),
			len(n.mappedValues),
		)
	}

	if len(n.openingProofs) !=
		len(n.mappedValues) {

		return fmt.Errorf(
			"leaf %d has %d mapped values but %d opening proofs",
			*leafNumber,
			len(n.mappedValues),
			len(n.openingProofs),
		)
	}

	if len(n.evaluationPoints) !=
		len(n.openingProofs) {

		return fmt.Errorf(
			"leaf %d has %d opening proofs but %d evaluation points",
			*leafNumber,
			len(n.openingProofs),
			len(n.evaluationPoints),
		)
	}

	if n.commitment == nil {
		return fmt.Errorf(
			"leaf %d has no commitment",
			*leafNumber,
		)
	}

	if n.nodeSRS == nil {
		return fmt.Errorf(
			"leaf %d has no SRS",
			*leafNumber,
		)
	}

	// ============================================================
	// LEAF HEADER
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("LEAF %d OPENING PROOFS\n", *leafNumber)
	fmt.Println("============================================================")

	fmt.Println()
	fmt.Println("Entries:")

	for i, entry := range n.entries {

		fmt.Printf(
			"  key %v -> global evaluation point %d\n",
			entry.Key,
			n.evaluationPoints[i],
		)
	}

	commitmentBytes :=
		n.commitment.Bytes()

	fmt.Println()
	fmt.Printf(
		"Leaf commitment C = %x\n",
		commitmentBytes,
	)

	// ============================================================
	// ONE OPENING + PAIRING CHECK PER LEAF ENTRY
	// ============================================================

	for i := range n.openingProofs {

		proof :=
			&n.openingProofs[i]

		evaluationPoint :=
			n.evaluationPoints[i]

		// --------------------------------------------------------
		// Convert global evaluation point to BN254 field element.
		// --------------------------------------------------------

		var point fr.Element

		point.SetUint64(
			evaluationPoint,
		)

		// --------------------------------------------------------
		// Expected mapped value.
		// --------------------------------------------------------

		expectedMapped :=
			n.mappedValues[i]

		var expectedElement fr.Element

		expectedElement.SetBigInt(
			expectedMapped,
		)

		// --------------------------------------------------------
		// Claimed value stored inside the KZG opening proof.
		// --------------------------------------------------------

		var claimedBig big.Int

		proof.ClaimedValue.BigInt(
			&claimedBig,
		)

		claimedMatches :=
			proof.ClaimedValue.Equal(
				&expectedElement,
			)

		// --------------------------------------------------------
		// Opening proof group element.
		// --------------------------------------------------------

		proofBytes :=
			proof.H.Bytes()

		fmt.Println()
		fmt.Println("------------------------------------------------------------")

		fmt.Printf(
			"OPENING %d\n",
			i,
		)

		fmt.Println("------------------------------------------------------------")

		fmt.Printf(
			"key                        = %v\n",
			n.entries[i].Key,
		)

		fmt.Printf(
			"global evaluation point z = %d\n",
			evaluationPoint,
		)

		fmt.Printf(
			"expected mapped value y    = %s\n",
			expectedMapped.String(),
		)

		fmt.Printf(
			"proof claimed value        = %s\n",
			claimedBig.String(),
		)

		fmt.Printf(
			"claimed value == expected  = %v\n",
			claimedMatches,
		)

		fmt.Printf(
			"opening proof pi            = %x\n",
			proofBytes,
		)

		// ========================================================
		// PRINT KZG PAIRING RELATION
		// ========================================================

		fmt.Println()
		fmt.Println("KZG pairing equation:")

		fmt.Println()
		fmt.Println("  e(C - yG1, G2)")
		fmt.Println()
		fmt.Println("          =")
		fmt.Println()
		fmt.Println("  e(pi, [tau]G2 - zG2)")
		fmt.Println()

		fmt.Printf(
			"where z = %d\n",
			evaluationPoint,
		)

		fmt.Printf(
			"      y = %s\n",
			expectedMapped.String(),
		)

		fmt.Printf(
			"      C = %x\n",
			commitmentBytes,
		)

		fmt.Printf(
			"     pi = %x\n",
			proofBytes,
		)

		// ========================================================
		// PRINT VERIFICATION-KEY G2 VALUES
		// ========================================================

		fmt.Println()
		fmt.Println("Verification-key G2 elements:")

		for j := range n.nodeSRS.Vk.G2 {

			g2Bytes :=
				n.nodeSRS.Vk.G2[j].Bytes()

			fmt.Printf(
				"  VK.G2[%d] = %x\n",
				j,
				g2Bytes,
			)
		}

		// ========================================================
		// ACTUAL KZG PAIRING VERIFICATION
		// ========================================================

		err :=
			kzg.Verify(
				n.commitment,
				proof,
				point,
				n.nodeSRS.Vk,
			)

		fmt.Println()
		fmt.Println("Pairing verification:")

		if err != nil {

			fmt.Println(
				"  RESULT = FAILED",
			)

			fmt.Printf(
				"  error  = %v\n",
				err,
			)

			return fmt.Errorf(
				"leaf %d opening %d failed KZG pairing verification at global evaluation point %d: %w",
				*leafNumber,
				i,
				evaluationPoint,
				err,
			)
		}

		fmt.Println(
			"  RESULT = PASSED",
		)
	}

	// ============================================================
	// COMPLETE LEAF RESULT
	// ============================================================

	fmt.Println()
	fmt.Println("------------------------------------------------------------")

	fmt.Printf(
		"LEAF %d: ALL %d KZG OPENING PAIRINGS PASSED\n",
		*leafNumber,
		len(n.openingProofs),
	)

	fmt.Println("------------------------------------------------------------")

	*leafNumber =
		*leafNumber + 1

	return nil
}
