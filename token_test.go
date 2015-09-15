// Copyright 2015 Joseph Spurrier
// Author: Joseph Spurrier (http://josephspurrier.com)
// License: http://www.apache.org/licenses/LICENSE-2.0.html

package csrfbanana

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gorilla/sessions"
)

func TestGenerate(t *testing.T) {
	token := generate(TokenLength)
	length := len(token)

	if length != TokenLength {
		t.Errorf("Wrong token length: expected %d, got %d", TokenLength, length)
	}
}

func TestToken(t *testing.T) {
	var cookieName = "test"
	TokenName = "foo"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the request
	r := fakeGet()

	// Get the session
	sess, err := store.Get(r, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	token := Token(w, r, sess)

	if token != sess.Values[TokenName].(StringMap)["/"] {
		t.Errorf("Tokens do not match: expected %v, got %v", sess.Values[TokenName], token)
	}

	// Reset the token name
	TokenName = "token"
}

func TestTokenWithPath(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the request
	r := fakeGet()

	// Get the session
	sess, err := store.Get(r, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	token := TokenWithPath(w, r, sess, "/monkey")

	if token != sess.Values[TokenName].(StringMap)["/monkey"] {
		t.Errorf("Tokens do not match: expected %v, got %v", token, sess.Values[TokenName])
	}
}

func TestTokenWithPathMaxTokens(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the request
	r := fakeGet()

	// Get the session
	sess, err := store.Get(r, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	for i := 0; i < MaxTokens; i++ {
		TokenWithPath(w, r, sess, "/monkey"+fmt.Sprintf("%v", i))
	}

	token := TokenWithPath(w, r, sess, "/monkey")

	if token != sess.Values[TokenName].(StringMap)["/monkey"] {
		t.Errorf("Tokens do not match: expected %v, got %v", token, sess.Values[TokenName])
	}
}

func TestTokenMaxTokens(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the request
	r := fakeGet()

	// Get the session
	sess, err := store.Get(r, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	for i := 0; i < MaxTokens; i++ {
		TokenWithPath(w, r, sess, "/monkey"+fmt.Sprintf("%v", i))
	}

	token := Token(w, r, sess)

	if token != sess.Values[TokenName].(StringMap)["/"] {
		t.Errorf("Tokens do not match: expected %v, got %v", token, sess.Values[TokenName])
	}
}

func TestNotMatch(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/"] = "123456fffff"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestMatch(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/"] = "123456"

	if ok := match(req, sess, true); !ok {
		t.Error("Tokens do not match")
	}
}

func TestMatchReferer(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/login", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Pretend the page URL is /loginform
	req.Header.Set("Referer", "http://localhost/loginform")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/loginform"] = "123456"

	if ok := match(req, sess, true); !ok {
		t.Error("Tokens do not match")
	}
}

func TestMatchRefererFail(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/login", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Pretend the page URL is /loginform, but the referrer is not set
	//req.Header.Set("Referer", "http://localhost/loginform")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/loginform"] = "123456"

	if ok := match(req, sess, true); ok {
		t.Error("Tokens should not match")
	}
}

func TestSingleTokenPerSession(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Use single token
	SingleToken = true

	// Create the GET request
	req, err := http.NewRequest("GET", "http://localhost/test1", nil)
	if err != nil {
		panic(err)
	}

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	token1 := Token(w, req, sess)

	// Create the GET request
	req2, err := http.NewRequest("GET", "http://localhost/test2", nil)
	if err != nil {
		panic(err)
	}

	token2 := Token(w, req2, sess)

	if token1 != token2 {
		t.Errorf("Tokens should match: expected %v, got %v", token1, token2)
	}
}

func TestUniqueTokenPerPage(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Use unique token per page
	SingleToken = false

	// Create the GET request
	req, err := http.NewRequest("GET", "http://localhost/test1", nil)
	if err != nil {
		panic(err)
	}

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	token1 := Token(w, req, sess)

	// Create the GET request
	req2, err := http.NewRequest("GET", "http://localhost/test2", nil)
	if err != nil {
		panic(err)
	}

	token2 := Token(w, req2, sess)

	if token1 == token2 {
		t.Error("Tokens should not match")
	}
}

func TestMatchSingleToken(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Use same token per session
	SingleToken = true

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/test", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/"] = "123456"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("The request should have been successful, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestMatchUniqueToken(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Use unique token per page
	SingleToken = false

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/test", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)
	sess.Values[TokenName].(StringMap)["/"] = "123456"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestClear(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the request
	r := fakeGet()

	// Get the session
	sess, err := store.Get(r, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Generate a token
	Token(w, r, sess)

	// Clear the token
	Clear(w, r, sess)

	if _, ok := sess.Values[TokenName]; ok {
		t.Errorf("StringMap should not exist: expected %v, got %v", nil, reflect.TypeOf(sess.Values[TokenName]))
	}
}
