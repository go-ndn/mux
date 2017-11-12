package mux

//go:generate gorewrite

func init() {
	routeNodeValEmpty = func(t Handler) bool {
		return t == nil
	}
}
