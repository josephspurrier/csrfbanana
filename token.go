package csrfbanana

// Great information:
// Cheatsheet: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
// Per Request vs Per Session: http://stackoverflow.com/questions/10466241/new-csrf-token-per-request-or-not
// Nosurf: https://github.com/justinas/nosurf
// Martini: https://github.com/martini-contrib/csrf
// Revel: https://github.com/cbonello/revel-csrf

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

var (
	TokenLength = 32      // Length of the token
	TokenName   = "token" // Name of the token in the session variables
	SingleToken = false   // True is one token for entire session, false is unique token for each URL
	MaxTokens   = 20      // Maximum number of tokens saved in a session - prevents this error: Error saving session: securecookie: the value is too long
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

		if len(sessMap) >= MaxTokens {
			for i, _ := range sessMap {
				delete(sessMap, i)
			}
		}

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

		if len(sessMap) >= MaxTokens {
			for i, _ := range sessMap {
				delete(sessMap, i)
			}
		}

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

	// If tokens exists
	if token, ok := sess.Values[TokenName]; ok {

		// Token submitted via POST
		sentToken := r.FormValue(TokenName)

		// Detect the content type
		switch r.Header.Get("Content-Type") {
		case "application/x-www-form-urlencoded":
			sentToken = r.FormValue(TokenName)
			break
		case "application/json":
			// Prevents throwing an error if nil
			b := bytes.NewBuffer(make([]byte, 0))
			body_reader := io.TeeReader(r.Body, b)
			if r.Body == nil {
				break
			}
			var t interface{}
			decoder := json.NewDecoder(body_reader)
			err := decoder.Decode(&t)

			// If the response is JSON
			if err == nil {
				vals := t.(map[string]interface{})
				// Update the token value
				sentToken = fmt.Sprintf("%v", vals[TokenName])
			}
			r.Body = ioutil.NopCloser(b)
			break
		}

		// If token is empty in the form, it is not valid
		if sentToken == "" {
			valid = false
		} else {
			// Check token against same page URL
			if sentToken == token.(StringMap)[path] {
				valid = true
			} else {
				// Extract the relative referer path
				offset := strings.Index(r.Referer(), r.Host) + len(r.Host)

				// Make sure no errors can be thrown
				if offset != 0 && offset < len(r.Referer()) {
					// Check token against previous page
					if sentToken == token.(StringMap)[r.Referer()[offset:]] {
						valid = true
					}
				}

			}
		}

		if refresh {
			delete(token.(StringMap), path)
		}
	}

	return valid
}
