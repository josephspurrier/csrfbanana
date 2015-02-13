// Copyright 2015 Joseph Spurrier
// Author: Joseph Spurrier (http://josephspurrier.com)
// License: http://www.apache.org/licenses/LICENSE-2.0.html

package csrfbanana

import (
	"bytes"
	"net/http"
	"net/url"
)

func fakeGet() *http.Request {
	r, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		panic(err)
	}
	return r
}

func fakePost(values url.Values) *http.Request {
	r, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(values.Encode()))
	if err != nil {
		panic(err)
	}
	return r
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("success"))
}

func failureHandler500(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
	w.Write([]byte("error"))
}
