package mux

//go:generate generic github.com/go-ndn/lpm/matcher .route Type->Handler TypeMatcher->routeMatcher

func init() {
	routeNodeValEmpty = func(t Handler) bool {
		return t == nil
	}
}
