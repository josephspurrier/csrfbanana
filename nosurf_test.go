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
	"net/url"
	"testing"
)

func TestSContains(t *testing.T) {
	slice := []string{"abc", "def", "ghi"}

	s1 := "abc"
	if !sContains(slice, s1) {
		t.Errorf("sContains said that %v doesn't contain %v, but it does.", slice, s1)
	}

	s2 := "xyz"
	if sContains(slice, s2) {
		t.Errorf("sContains said that %v contains %v, but it doesn't.", slice, s2)
	}
}

func TestSameOrigin(t *testing.T) {
	// a little helper that saves us time
	p := func(rawurl string) *url.URL {
		u, err := url.Parse(rawurl)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	truthy := [][]*url.URL{
		{p("http://dummy.us/"), p("http://dummy.us/faq")},
		{p("https://dummy.us/some/page"), p("https://dummy.us/faq")},
	}

	falsy := [][]*url.URL{
		// different ports
		{p("http://dummy.us/"), p("http://dummy.us:8080")},
		// different scheme
		{p("https://dummy.us/"), p("http://dummy.us/")},
		// different host
		{p("https://dummy.us/"), p("http://dummybook.us/")},
		// slightly different host
		{p("https://beta.dummy.us/"), p("http://dummy.us/")},
	}

	for _, v := range truthy {
		if !sameOrigin(v[0], v[1]) {
			t.Errorf("%v and %v have the same origin, but sameOrigin() said otherwise.",
				v[0], v[1])
		}
	}

	for _, v := range falsy {
		if sameOrigin(v[0], v[1]) {
			t.Errorf("%v and %v don't have the same origin, but sameOrigin() said otherwise.",
				v[0], v[1])
		}
	}

}
