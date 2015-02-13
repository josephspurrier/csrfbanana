// Source: https://github.com/justinas/nosurf
/*
The MIT License (MIT)

Copyright (c) 2013 Justinas Stankevicius

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package csrfbanana

import (
	"fmt"
	"net/http"
	"net/url"
)

const (
	// the HTTP status code for the default failure handler
	FailureCode = 400
)

var (
	safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

// Checks if the given URLs have the same origin
// (that is, they share the host, the port and the scheme)
func sameOrigin(u1, u2 *url.URL) bool {
	// we take pointers, as url.Parse() returns a pointer
	// and http.Request.URL is a pointer as well

	// Host is either host or host:port
	return (u1.Scheme == u2.Scheme && u1.Host == u2.Host)
}

func sContains(slice []string, s string) bool {
	// checks if the given slice contains the given string
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(FailureCode)
	fmt.Fprint(w, "Bad Request 400")
}
