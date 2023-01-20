package main

// type CustomMux struct {
// 	http.ServeMux
// 	Middlewares []func(next http.Handler) http.Handler
// }

// func (c *CustomMux) RegisterMiddleware(next func(nex http.Handler) http.Handler) {
// 	c.Middlewares = append(c.Middlewares, next)
// }

// func (c *CustomMux) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
// 	var current http.Handler = &c.ServeMux

// 	for _, next := range c.Middlewares {
// 		current = next(current)
// 	}

// 	current.ServeHTTP(writer, request)
// }
