//go:build appengine
// +build appengine

package softblake3

// WriteString adds more data to the running hash.
// It never returns an error.
func (g *Hasher) WriteString(b string) (n int, err error) {
	return g.Write([]byte(b))
}
