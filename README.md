CSRFBanana
==========
[![Build Status](https://travis-ci.org/josephspurrier/csrfbanana.svg)](https://travis-ci.org/josephspurrier/csrfbanana) [![Coverage Status](https://coveralls.io/repos/josephspurrier/csrfbanana/badge.svg)](https://coveralls.io/r/josephspurrier/csrfbanana) [![GoDoc](https://godoc.org/github.com/josephspurrier/csrfbanana?status.svg)](https://godoc.org/github.com/josephspurrier/csrfbanana)

CSRF Protection for [gorilla/sessions](http://www.gorillatoolkit.org/pkg/sessions) in the Go Language

CSRFBanana is a middleware package that helps prevent cross-site request forgery attacks. The package can generate tokens per session or per page. Tokens can also be regenerated after a successful or failed attempt to validate.

In this package, the CSRF tokens are stored in the (same) session cookie that is handled by gorilla/sessions. You can read about the different CSRF approaches on StackOverflow: [Why is it common to put CSRF prevention tokens in cookies?](http://stackoverflow.com/a/20518324)

## Usage

Import the package:

~~~ go
import "github.com/josephspurrier/csrfbanana"
~~~

Configure the package as middleware:

~~~ go
// Default handler
h := http.HandlerFunc(YourOwnDefaultFunction)

// Insert the CSRFBanana here to prevent CSRF
cs := csrfbanana.New(h, Store, SessionName)

// Set error page for CSRF failures
cs.FailureHandler(http.HandlerFunc(routeInvalidToken))

// Generate a new token after each success/failure (also prevents double submits)
cs.ClearAfterUsage(true)

// Exclude routes like /static/ from token generation/checking
cs.ExcludeRegexPaths([]string{"/static(.*)"})

// Set the token length (default is 32)
csrfbanana.TokenLength = 32

// Set the max number of tokens stored per session (default is 20)
csrfbanana.MaxTokens = 20

// Set the token name used in the forms and session (default is token)
csrfbanana.TokenName = "token"

// Set the token to generate per page (false - the default) or per session (true)
csrfbanana.SingleToken = false

// Pass the handler to your HTTP server
http.ListenAndServe(":80", cs)
~~~

Generate the token before passing to your templates:

~~~ go
// Create a map for the template
vars := make(map[string]string)

// Store the CSRF token to the map
vars["token"] = csrfbanana.Token(w, r, sess)

// Show the template
templ.Execute(w, vars)
~~~

Add the token to every POST form that is not excluded by ExcludeRegexPaths():

~~~ html
<input type="hidden" name="token" value="{{.token}}">
~~~

Note: Any other POST operation needs to either include the token or be added to ExcludeRegexPaths().

## Multiple Forms on the Same Page

To add tokens to multiple forms on the same page, use TokenWithPath() to specify the URL where the data will be submitted:

~~~ go
// Store token 1
vars["token1"] = csrfbanana.TokenWithPage(w, r, sess, "/form1")

// Store token 2
vars["token2"] = csrfbanana.TokenWithPage(w, r, sess, "/form2")
~~~

Then insert the tokens into the template:

~~~ html
<!-- Form 1 -->
<form method="post" action="/form1">
...
<input type="hidden" name="token" value="{{.token1}}">
</form>

<!-- Form 2 -->
<form method="post" action="/form2">
...
<input type="hidden" name="token" value="{{.token2}}">
</form>
~~~

## Working Example

To see the example in action, use the following commands:
~~~
go get github.com/josephspurrier/csrfbanana/example
go run src/github.com/josephspurrier/csrfbanana/example/example.go
~~~

## Major Contributions

Thanks to [Justinas Stankevičius](https://github.com/justinas/nosurf) for his CSRF package which I used as a solid example.