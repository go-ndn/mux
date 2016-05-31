package mux

import "github.com/go-ndn/lpm"

type routeMatcher struct {
	routeNode
}

var routeNodeValEmpty func(Handler) bool

type routeNode struct {
	val   Handler
	table map[string]routeNode
}

func (n *routeNode) empty() bool {
	return routeNodeValEmpty(n.val) && len(n.table) == 0
}

func (n *routeNode) update(key []lpm.Component, depth int, f func([]lpm.Component, Handler) Handler, exist, all bool) {
	try := func() {
		if depth == 0 {
			return
		}
		if !exist || !routeNodeValEmpty(n.val) {
			n.val = f(key[:depth], n.val)
		}
	}
	if len(key) == depth {
		try()
		return
	}

	if n.table == nil {
		if exist {
			try()
			return
		}
		n.table = make(map[string]routeNode)
	}

	v, ok := n.table[string(key[depth])]
	if !ok {
		if exist {
			try()
			return
		}
	}

	if all {
		try()
	}

	v.update(key, depth+1, f, exist, all)
	if v.empty() {
		delete(n.table, string(key[depth]))
	} else {
		n.table[string(key[depth])] = v
	}
}

func (n *routeNode) match(key []lpm.Component, depth int, f func(Handler), exist bool) {
	try := func() {
		if depth == 0 {
			return
		}
		if !exist || !routeNodeValEmpty(n.val) {
			f(n.val)
		}
	}
	if len(key) == depth {
		try()
		return
	}

	if n.table == nil {
		if exist {
			try()
		}
		return
	}

	v, ok := n.table[string(key[depth])]
	if !ok {
		if exist {
			try()
		}
		return
	}

	v.match(key, depth+1, f, exist)
}

func (n *routeNode) visit(key []lpm.Component, f func([]lpm.Component, Handler) Handler) {
	if !routeNodeValEmpty(n.val) {
		n.val = f(key, n.val)
	}
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
		if v.empty() {
			delete(n.table, k)
		} else {
			n.table[k] = v
		}
	}
}

func (n *routeNode) Update(key []lpm.Component, f func(Handler) Handler, exist bool) {
	n.update(key, 0, func(_ []lpm.Component, v Handler) Handler {
		return f(v)
	}, exist, false)
}

func (n *routeNode) UpdateAll(key []lpm.Component, f func([]lpm.Component, Handler) Handler, exist bool) {
	n.update(key, 0, f, exist, true)
}

func (n *routeNode) Match(key []lpm.Component, f func(Handler), exist bool) {
	n.match(key, 0, f, exist)
}

func (n *routeNode) Visit(f func([]lpm.Component, Handler) Handler) {
	key := make([]lpm.Component, 0, 16)
	n.visit(key, f)
}
