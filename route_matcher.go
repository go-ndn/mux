package mux

import (
	"github.com/go-ndn/lpm"
)

type routeMatcher struct{ routeNode }
type routeNode struct {
	val   *Handler
	table map[string]*routeNode
}

func (n *routeNode) Empty() bool {
	return n.val == nil && len(n.table) == 0
}
func routeDeref(val *Handler) (Handler, bool) {
	if val == nil {
		var t Handler
		return t, false
	}
	return *val, true
}
func (n *routeNode) Match(key []lpm.Component) (val Handler, found bool) {
	if len(key) == 0 {
		return routeDeref(n.val)
	}
	if n.table == nil {
		return routeDeref(n.val)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return routeDeref(n.val)
	}
	return child.Match(key[1:])
}
func (n *routeNode) Get(key []lpm.Component) (val Handler, found bool) {
	if len(key) == 0 {
		return routeDeref(n.val)
	}
	if n.table == nil {
		return routeDeref(nil)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return routeDeref(nil)
	}
	return child.Get(key[1:])
}
func (n *routeNode) Update(key []lpm.Component, val Handler) {
	if len(key) == 0 {
		n.val = &val
		return
	}
	if n.table == nil {
		n.table = make(map[string]*routeNode)
	}
	if _, ok := n.table[string(key[0])]; !ok {
		n.table[string(key[0])] = &routeNode{}
	}
	n.table[string(key[0])].Update(key[1:], val)
}
func (n *routeNode) Delete(key []lpm.Component) {
	if len(key) == 0 {
		n.val = nil
		return
	}
	if n.table == nil {
		return
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return
	}
	child.Delete(key[1:])
	if child.Empty() {
		delete(n.table, string(key[0]))
	}
}

type routeUpdateFunc func([]lpm.Component, Handler) (val Handler, del bool)

func (n *routeNode) UpdateAll(key []lpm.Component, f routeUpdateFunc) {
	for i := len(key); i > 0; i-- {
		k := key[:i]
		val, _ := n.Get(k)
		val2, del := f(k, val)
		if !del {
			n.Update(k, val2)
		} else {
			n.Delete(k)
		}
	}
}
func (n *routeNode) visit(key []lpm.Component, f func([]lpm.Component)) {
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
	}
	if n.val != nil {
		f(key)
	}
}
func (n *routeNode) Visit(f routeUpdateFunc) {
	n.visit(make([]lpm.Component, 0, 16), func(k []lpm.Component) {
		val, found := n.Get(k)
		if found {
			val2, del := f(k, val)
			if !del {
				n.Update(k, val2)
			} else {
				n.Delete(k)
			}
		}
	})
}
