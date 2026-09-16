package bptree

// Search looks for a key in the B+ tree.
//
// It returns:
//
//   value = H(key)
//   found = true
//
// if the key exists.
func (t *Tree[K, V]) Search(key K) ([32]byte, bool) {
	current := t.root

	// Traverse internal nodes.
	for !current.isLeaf {
		i := 0

		for i < len(current.keys) &&
			t.compare(key, current.keys[i]) >= 0 {

			i++
		}

		current = current.children[i]
	}

	// Search inside the leaf entries.
	for _, entry := range current.entries {

		cmp := t.compare(key, entry.Key)

		if cmp == 0 {
			return entry.Value, true
		}

		if cmp < 0 {
			break
		}
	}

	// Key not found.
	var zero [32]byte
	return zero, false
}