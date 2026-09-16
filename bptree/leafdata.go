package bptree

import (
	"fmt"
)

// PrintLeafData prints the complete contents of every leaf.
//
// For every entry it displays:
//
//   Key
//   Value = H(Key)
//   Mapped value in Z_p
//
// The relationship is:
//
//   entries[i] <--> mappedValues[i]
func (t *Tree[K, V]) PrintLeafData() {

	if t.root == nil {
		fmt.Println("<empty tree>")
		return
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LEAF DATA")
	fmt.Println("============================================================")
	fmt.Println()

	// Find the leftmost leaf.
	current := t.root

	for !current.isLeaf {
		current = current.children[0]
	}

	leafNumber := 0

	// Walk through the linked list of leaves.
	for current != nil {

		fmt.Printf("Leaf %d\n", leafNumber)
		fmt.Println("------------------------------------------------------------")

		for i, entry := range current.entries {

			fmt.Printf("Entry %d\n", i)

			fmt.Printf(
				"  Key          : %v\n",
				entry.Key,
			)

			// Print the complete 32-byte SHA-256 value.
			fmt.Printf(
				"  Value H(key) : %x\n",
				entry.Value,
			)

			// Print corresponding Z_p value.
			if i < len(current.mappedValues) &&
				current.mappedValues[i] != nil {

				fmt.Printf(
					"  Z_p value    : %s\n",
					current.mappedValues[i].String(),
				)

			} else {

				fmt.Println(
					"  Z_p value    : <missing>",
				)
			}

			fmt.Println()
		}

		current = current.next
		leafNumber++
	}
}