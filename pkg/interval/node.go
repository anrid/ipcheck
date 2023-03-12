// NOTE: Most of this code has been copied directly from https://github.com/obitech/go-trees
// All cred goes to the author.
package interval

type node struct {
	key     Interval
	color   color
	left    *node
	right   *node
	parent  *node
	max     uint32
	payload interface{}
}
