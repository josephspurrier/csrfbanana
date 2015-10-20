// Copyright 2015 Joseph Spurrier
// Author: Joseph Spurrier (http://josephspurrier.com)
// License: http://www.apache.org/licenses/LICENSE-2.0.html

package csrfbanana

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/sessions"
)

func TestDefaultFailureHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := fakeGet()

	defaultFailureHandler(w, r)

	if w.Code != FailureCode {
		t.Errorf("Wrong status code for defaultFailure Handler: "+
			"expected %d, got %d", FailureCode, w.Code)
	}
}

func TestCSRF(t *testing.T) {
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
	sess.Values[TokenName].(StringMap)["/"] = "123456"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestCSRFJSON(t *testing.T) {
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

	jsonValue := `{"token": "` + token + `"}`

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(jsonValue))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

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
		t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestCSRFMissingToken(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Create the POST request with no token
	req, err := http.NewRequest("POST", "http://localhost/", nil)
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

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestCSRFMissingTokenJSON(t *testing.T) {
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

	jsonValue := `{"token2": "` + token + `"}`

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(jsonValue))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

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

func TestCSRFMissingTokenJSONNoPayload(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Create the POST request with no token
	req, err := http.NewRequest("POST", "http://localhost/", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Get the session
	sess, err := store.Get(req, cookieName)
	if err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Set the values in the session manually
	sess.Values[TokenName] = make(StringMap)

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestCSRFMissingMap(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Create the POST request with no token
	req, err := http.NewRequest("POST", "http://localhost/", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestCSRFTokenBackend(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)

	// Create the form
	form := url.Values{}

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewBufferString(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestFailureHandler(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)
	h.FailureHandler(http.HandlerFunc(failureHandler500))

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
	sess.Values[TokenName].(StringMap)["/"] = "123456ffffff"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestClearAfterUsage(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)
	h.ClearAfterUsage(true)

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
	sess.Values[TokenName].(StringMap)["/"] = "123456ffffff"

	// Run the page
	h.ServeHTTP(w, req)

	if _, ok := sess.Values[TokenName].(StringMap)["/"]; ok {
		t.Error("The token should have been deleted.")
	}
}

func TestDontClearAfterUsage(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)
	h.ClearAfterUsage(false)

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
	sess.Values[TokenName].(StringMap)["/"] = "123456ffffff"

	// Run the page
	h.ServeHTTP(w, req)

	if _, ok := sess.Values[TokenName].(StringMap)["/"]; !ok {
		t.Error("The token should not have been deleted.")
	}
}

func TestIsExempt(t *testing.T) {
	var cookieName = "test"

	// Create a cookiestore
	store := sessions.NewCookieStore([]byte("secret-key"))

	// Create the recorder
	w := httptest.NewRecorder()

	// Create the handler
	h := New(http.HandlerFunc(successHandler), store, cookieName)
	h.ExcludeRegexPaths([]string{"/skip(.*)"})

	// Create the form
	token := "123456"
	form := url.Values{}
	form.Set(TokenName, token)

	// Create the POST request
	req, err := http.NewRequest("POST", "http://localhost/skip", bytes.NewBufferString(form.Encode()))
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
	sess.Values[TokenName].(StringMap)["/"] = "123456ffffff"

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("The request should have been successful, but it wasn't. Instead, the code was %d",
			w.Code)
	}
}

func TestBadReferer(t *testing.T) {
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
	req, err := http.NewRequest("POST", "https://localhost/", bytes.NewBufferString(form.Encode()))
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

	req.Header.Set("Referer", `/asd/;';(*)*#*%(&*\`)

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}

func TestSameOriginBlock(t *testing.T) {
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
	req, err := http.NewRequest("POST", "https://localhost/", bytes.NewBufferString(form.Encode()))
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

	req.Header.Set("Referer", "http://google.com")

	// Run the page
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		t.Errorf("The request should have failed, but it didn't. Instead, the code was %d",
			w.Code)
	}
}
