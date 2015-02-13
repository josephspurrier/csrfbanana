package main

import (
	"fmt"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/josephspurrier/csrfbanana"
)

var (
	Store       *sessions.CookieStore
	SessionName = "banana"
)

var templateString string = `
<!DOCTYPE html>
<html>
<body>

<!-- Only show if after a POST that contains name -->
{{ if .name }}
<p>Your name: {{ .name }}</p>
<p>Tip: Try to reload the page...</p>
{{ end }}

<!-- Form with a token -->
<div style="margin: 20px 0 20px 20px">
<form action="/" method="POST">
	<label for="name" style="width: 120px; display: inline-block;">Enter your name:</label>
	<input type="text" name="name" id="name">
	<!-- This is where you add the token to every form that you POST -->
	<input type="hidden" name="token" value="{{.token}}">
	<input type="submit" value="Submit with Token" style="width: 160px;">
</form>
</div>

<!-- Form without a Token -->
<div style="margin: 0 0 0 20px">
<form action="/" method="POST">
	<label for="num" style="width: 120px; display: inline-block;">Type in a number:</label>
	<input type="text" name="num" id="num">
	<!-- You can see this form is missing a token so it will fail  -->
	<input type="submit" value="Submit without Token" style="width: 160px;">
</form>
</div>

</body>
</html>
`

// Compiled template
var templ = template.Must(template.New("t1").Parse(templateString))

// Login handles GET and POST
func routeLogin(w http.ResponseWriter, r *http.Request) {

	// Get session
	sess := Session(r, SessionName)

	// Create a map for the template
	vars := make(map[string]string)

	// Store the CSRF token
	vars["token"] = csrfbanana.Token(w, r, sess)

	// If a POST operation
	if r.Method == "POST" {
		// Store the name to a template variable
		vars["name"] = r.FormValue("name")
	}

	// Show the template
	templ.Execute(w, vars)
}

// InvalidToken handles CSRF attacks
func routeInvalidToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `Your token <strong>expired</strong>, click <a href="javascript:void(0)" onclick="window.history.back()">here</a> to try again.`)
}

// Session returns a new session, never returns an error
func Session(r *http.Request, name string) *sessions.Session {
	session, _ := Store.Get(r, name)
	return session
}

func main() {
	// Create cookie store
	Store = sessions.NewCookieStore([]byte("This is super screen..."))
	Store.Options = &sessions.Options{
		//Domain:   "localhost", // Chrome doesn't work with localhost domain
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
	}

	// Default handler
	h := http.HandlerFunc(routeLogin)

	// Prevents CSRF
	cs := csrfbanana.New(h, Store, SessionName)

	// Set error page for CSRF
	cs.FailureHandler(http.HandlerFunc(routeInvalidToken))

	// Generate a new token after each check (also prevents double submits)
	cs.ClearAfterUsage(true)

	// Exclude /static/ from tokens (even though we don't have a static file handler...)
	cs.ExcludeRegexPaths([]string{"/static(.*)"})

	// Optional - set the token length
	csrfbanana.TokenLength = 32

	// Optional - set the token name used in the forms
	csrfbanana.TokenName = "token"

	fmt.Println("Listening on http://localhost:80/")
	http.ListenAndServe(":80", cs)
}
