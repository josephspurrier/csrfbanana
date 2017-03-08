// Package csrfbanana creates a token to protect against CSRF attacks
package csrfbanana

// Usage to set template variable from session variable:
// v.Vars["token"] = csrfbanana.Token(w, r, sess)
//
// Set in form:
// <input type="hidden" name="token" value="{{.token}}">

import (
	"encoding/gob"
	"net/http"
	"regexp"

	"github.com/gorilla/sessions"
)

// CSRFHandler contains the configuration for the CSRF structure
type CSRFHandler struct {
	failureHandler       http.Handler
	perRequest           int
	regenerateAfterUsage bool
	excludeRegexPaths    []*regexp.Regexp
	store                sessions.Store
	sessionName          string
	nextHandler          http.Handler
}

// StringMap has key of string and value of string
type StringMap map[string]string

func init() {
	// Magic goes here to allow serializing maps in securecookie
	// http://golang.org/pkg/encoding/gob/#Register
	// Source: http://stackoverflow.com/questions/21934730/gob-type-not-registered-for-interface-mapstringinterface
	gob.Register(StringMap{})
}

// New can be used as middleware because it returns an http.HandlerFunc
func New(next http.Handler, sessStore sessions.Store, sessName string) *CSRFHandler {
	cs := &CSRFHandler{}
	cs.nextHandler = next
	cs.failureHandler = http.HandlerFunc(defaultFailureHandler)
	cs.store = sessStore
	cs.sessionName = sessName
	return cs
}

// RegenerateEveryRequest will regenerate a token everytime it's checked (prevents double submit problem)
func (h *CSRFHandler) ClearAfterUsage(bl bool) {
	h.regenerateAfterUsage = bl
}

// ExcludeRegexPath excludes a list of paths from the token middleware
func (h *CSRFHandler) ExcludeRegexPaths(strings []string) {
	for _, re := range strings {
		compiled := regexp.MustCompile(re)
		h.excludeRegexPaths = append(h.excludeRegexPaths, compiled)
	}
}

// FailureHandler sets the handler if the token check fails
func (h *CSRFHandler) FailureHandler(handler http.Handler) {
	h.failureHandler = handler
}

// ServeHTTP will valid a token and it is does not match, it will show the FailureHandler
func (h *CSRFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.isExempt(r.URL.Path) {

		// *********************************************************************
		// Source: https://github.com/justinas/nosurf/blob/master/handler.go
		// MIT License in nosurf.go
		//
		// if the request is secure, we enforce origin check
		// for referer to prevent MITM of http->https requests
		if r.URL.Scheme == "https" {
			referer, err := r.URL.Parse(r.Header.Get("Referer"))

			// if we can't parse the referer or it's empty,
			// we assume it's not specified
			if err != nil || referer.String() == "" {
				h.failureHandler.ServeHTTP(w, r)
				return
			}

			// if the referer doesn't share origin with the request URL,
			// we have another error for that
			if !sameOrigin(referer, r.URL) {
				h.failureHandler.ServeHTTP(w, r)
				return
			}
		}
		// *********************************************************************

		// Get the session
		sess, _ := h.store.Get(r, h.sessionName)

		isMatch := true

		// If method is POST, PUT, or DELETE
		if !sContains(safeMethods, r.Method) {
			// Determine if the token matches
			isMatch = match(r, sess, h.regenerateAfterUsage)
		}

		// If the token does NOT match
		if !isMatch {
			// Serve the Failure Handler
			h.failureHandler.ServeHTTP(w, r)
			return
		}

	}

	// Serve the next handler
	h.nextHandler.ServeHTTP(w, r)
}

// Returns true if the current request is exempt
func (h *CSRFHandler) isExempt(url string) bool {
	for _, re := range h.excludeRegexPaths {
		if re.MatchString(url) {
			return true
		}
	}
	return false
}
