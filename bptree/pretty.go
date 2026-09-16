package bptree

import (
	"fmt"
	"strings"
)

const prettyGap = 4

// PrintPretty prints the B+ tree horizontally.
//
// Only keys are displayed in the tree so that the
// visualization remains readable.
//
// Leaf values H(key) are still stored internally.
func (t *Tree[K, V]) PrintPretty() {
	if t.root == nil {
		fmt.Println("<empty tree>")
		return
	}

	fmt.Printf("B+ Tree (order = %d)\n\n", t.order)

	// Find the widest leaf label.
	maxLeafWidth := prettyMaxLeafWidth(t.root)

	slotWidth := maxLeafWidth + prettyGap

	if slotWidth < 10 {
		slotWidth = 10
	}

	// Assign horizontal positions.
	positions := make(map[*node[K, V]]int)

	nextX := slotWidth / 2

	prettyAssignPositions(
		t.root,
		positions,
		&nextX,
		slotWidth,
	)

	// Collect nodes by depth.
	levels := make(map[int][]*node[K, V])

	maxDepth := 0

	prettyCollectLevels(
		t.root,
		0,
		levels,
		&maxDepth,
	)

	width := nextX + slotWidth/2

	for depth := 0; depth <= maxDepth; depth++ {

		// ==========================================
		// Print node labels
		// ==========================================

		labelLine := prettyBlankLine(width)

		for _, n := range levels[depth] {
			prettyPlaceText(
				labelLine,
				positions[n],
				prettyNodeLabel(n),
			)
		}

		prettyPrintLine(labelLine)

		if depth == maxDepth {
			break
		}

		// ==========================================
		// Parent vertical line
		// ==========================================

		parentLine := prettyBlankLine(width)

		for _, n := range levels[depth] {
			if n.isLeaf {
				continue
			}

			parentLine[positions[n]] = '│'
		}

		prettyPrintLine(parentLine)

		// ==========================================
		// Horizontal branches
		// ==========================================

		branchLine := prettyBlankLine(width)

		for _, n := range levels[depth] {
			if n.isLeaf {
				continue
			}

			firstX := positions[n.children[0]]
			lastX := positions[n.children[len(n.children)-1]]
			parentX := positions[n]

			for x := firstX; x <= lastX; x++ {
				branchLine[x] = '─'
			}

			branchLine[firstX] = '┌'
			branchLine[lastX] = '┐'

			// Mark every child position.
			for i, child := range n.children {
				childX := positions[child]

				if i == 0 || i == len(n.children)-1 {
					continue
				}

				branchLine[childX] = '┬'
			}

			// Connect parent downward into the branch.
			switch branchLine[parentX] {
			case '┬':
				branchLine[parentX] = '┼'
			case '┌', '┐':
				branchLine[parentX] = '┼'
			default:
				branchLine[parentX] = '┴'
			}
		}

		prettyPrintLine(branchLine)

		// ==========================================
		// Child vertical lines
		// ==========================================

		childLine := prettyBlankLine(width)

		for _, n := range levels[depth] {
			if n.isLeaf {
				continue
			}

			for _, child := range n.children {
				childLine[positions[child]] = '│'
			}
		}

		prettyPrintLine(childLine)
	}

	fmt.Println()

	prettyPrintLeafChain(t)
}

// prettyNodeLabel prints:
//
// Internal:
// [25 38 52]
//
// Leaf:
// [18 22]
//
// The hashes are intentionally omitted from the tree
// visualization to keep it compact.
func prettyNodeLabel[K any, V any](
	n *node[K, V],
) string {

	var builder strings.Builder

	builder.WriteString("[")

	if n.isLeaf {

		for i, entry := range n.entries {

			if i > 0 {
				builder.WriteString(" ")
			}

			builder.WriteString(
				fmt.Sprintf("%v", entry.Key),
			)
		}

	} else {

		for i, key := range n.keys {

			if i > 0 {
				builder.WriteString(" ")
			}

			builder.WriteString(
				fmt.Sprintf("%v", key),
			)
		}
	}

	builder.WriteString("]")

	return builder.String()
}

// Find maximum leaf label width.
func prettyMaxLeafWidth[K any, V any](
	n *node[K, V],
) int {

	if n.isLeaf {
		return len(prettyNodeLabel(n))
	}

	maxWidth := 0

	for _, child := range n.children {

		width := prettyMaxLeafWidth(child)

		if width > maxWidth {
			maxWidth = width
		}
	}

	return maxWidth
}

// Position leaves from left to right.
// Internal nodes are centered above their children.
func prettyAssignPositions[K any, V any](
	n *node[K, V],
	positions map[*node[K, V]]int,
	nextX *int,
	slotWidth int,
) {

	if n.isLeaf {

		positions[n] = *nextX

		*nextX += slotWidth

		return
	}

	for _, child := range n.children {
		prettyAssignPositions(
			child,
			positions,
			nextX,
			slotWidth,
		)
	}

	first := positions[n.children[0]]
	last := positions[n.children[len(n.children)-1]]

	positions[n] = (first + last) / 2
}

// Group nodes by depth.
func prettyCollectLevels[K any, V any](
	n *node[K, V],
	depth int,
	levels map[int][]*node[K, V],
	maxDepth *int,
) {

	levels[depth] = append(
		levels[depth],
		n,
	)

	if depth > *maxDepth {
		*maxDepth = depth
	}

	if n.isLeaf {
		return
	}

	for _, child := range n.children {
		prettyCollectLevels(
			child,
			depth+1,
			levels,
			maxDepth,
		)
	}
}

// Create a blank rune line.
func prettyBlankLine(width int) []rune {

	line := make([]rune, width)

	for i := range line {
		line[i] = ' '
	}

	return line
}

// Place text centered around x.
func prettyPlaceText(
	line []rune,
	center int,
	text string,
) {

	runes := []rune(text)

	start := center - len(runes)/2

	if start < 0 {
		start = 0
	}

	for i, r := range runes {

		pos := start + i

		if pos >= 0 && pos < len(line) {
			line[pos] = r
		}
	}
}

// Print a line without trailing spaces.
func prettyPrintLine(line []rune) {

	fmt.Println(
		strings.TrimRight(
			string(line),
			" ",
		),
	)
}

// Display the B+ tree leaf linked list.
func prettyPrintLeafChain[K any, V any](
	t *Tree[K, V],
) {

	fmt.Println("Leaf chain:")

	current := t.root

	// Find leftmost leaf.
	for !current.isLeaf {
		current = current.children[0]
	}

	for current != nil {

		fmt.Print("[")

		for i, entry := range current.entries {

			if i > 0 {
				fmt.Print(" ")
			}

			fmt.Printf("%v", entry.Key)
		}

		fmt.Print("]")

		if current.next != nil {
			fmt.Print(" -> ")
		}

		current = current.next
	}

	fmt.Println()
}