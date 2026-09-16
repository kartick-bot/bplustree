package bptree

import (
	"fmt"
	"strings"
)

// Print displays the B+ tree level by level.
func (t *Tree[K, V]) Print() {
	if t.root == nil {
		fmt.Println("<empty tree>")
		return
	}

	currentLevel := []*node[K, V]{t.root}

	level := 0

	for len(currentLevel) > 0 {

		fmt.Printf("Level %d: ", level)

		nextLevel := make([]*node[K, V], 0)

		var parts []string

		for _, n := range currentLevel {

			var builder strings.Builder

			builder.WriteString("[")

			for i, key := range n.keys {

				if i > 0 {
					builder.WriteString(" ")
				}

				builder.WriteString(fmt.Sprintf("%v", key))
			}

			builder.WriteString("]")

			parts = append(parts, builder.String())

			if !n.isLeaf {
				nextLevel = append(
					nextLevel,
					n.children...,
				)
			}
		}

		fmt.Println(strings.Join(parts, "   "))

		currentLevel = nextLevel
		level++
	}
}