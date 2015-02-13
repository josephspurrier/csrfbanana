// Copyright 2015 Joseph Spurrier
// Author: Joseph Spurrier (http://josephspurrier.com)
// License: http://www.apache.org/licenses/LICENSE-2.0.html

package csrfbanana

// Great information:
// Cheatsheet: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
// Per Request vs Per Session: http://stackoverflow.com/questions/10466241/new-csrf-token-per-request-or-not
// Nosurf: https://github.com/justinas/nosurf
// Martini: https://github.com/martini-contrib/csrf
// Revel: https://github.com/cbonello/revel-csrf

import (
	"crypto/rand"
	"net/http"

	"github.com/gorilla/sessions"
)

var (
	TokenLength = 32      // Length of the token
	TokenName   = "token" // Name of the token in the session variables
	SingleToken = false   // True is one token for entire session, false is unique token for each URL
)

// Clear will remove all the tokens. Call after a permission change.
func Clear(w http.ResponseWriter, r *http.Request, sess *sessions.Session) {
	// Delete the map if it doesn't exist
	if _, ok := sess.Values[TokenName]; ok {
		delete(sess.Values, TokenName)
		sess.Save(r, w)
	}
}

// Token will return a token. If SingleToken = true, it will return the same token for every page.
func Token(w http.ResponseWriter, r *http.Request, sess *sessions.Session) string {
	// Generate the map if it doesn't exist
	if _, ok := sess.Values[TokenName]; !ok {
		sess.Values[TokenName] = make(StringMap)
	}

	path := r.URL.Path

	if SingleToken {
		path = "/"
	}

	sessMap := sess.Values[TokenName].(StringMap)
	if _, ok := sessMap[path]; !ok {
		sessMap[path] = generate(TokenLength)
		sess.Save(r, w)
	}

	return sessMap[path]
}

// Token will return a token for the specified URL. SingleToken is ignored.
func TokenWithPath(w http.ResponseWriter, r *http.Request, sess *sessions.Session, urlPath string) string {
	// Generate the map if it doesn't exist
	if _, ok := sess.Values[TokenName]; !ok {
		sess.Values[TokenName] = make(StringMap)
	}

	sessMap := sess.Values[TokenName].(StringMap)
	if _, ok := sessMap[urlPath]; !ok {
		sessMap[urlPath] = generate(TokenLength)
		sess.Save(r, w)
	}

	return sessMap[urlPath]
}

// Generate a token
// Source: https://devpy.wordpress.com/2013/10/24/create-random-string-in-golang/
func generate(length int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, length)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}

	return string(bytes)
}

// If the form token matches the session token for the URL, return true
func match(r *http.Request, sess *sessions.Session, refresh bool) bool {

	valid := false
	path := r.URL.Path

	if SingleToken {
		path = "/"
	}

	if token, ok := sess.Values[TokenName]; ok {
		if r.FormValue(TokenName) == token.(StringMap)[path] && r.FormValue(TokenName) != "" {
			valid = true
		}

		if refresh {
			delete(token.(StringMap), path)
		}
	}

	return valid
}
