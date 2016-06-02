package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/cfmobile/oauth2-route-service/oauth/uaa"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
)

const (
	DEFAULT_PORT = "8080"
)

var skipSSLValidation bool

func init() {
	flag.BoolVar(&skipSSLValidation, "skipSSLValidation", false, "Skip SSL Validation for incoming requests and when talking to UAA")
	flag.Parse()
}

func main() {

	var port string
	if port = os.Getenv("PORT"); len(port) == 0 {
		port = DEFAULT_PORT
	}

	store := sessions.NewCookieStore([]byte("so-secret"))
	authService := uaa.NewAuthService(store, skipSSLValidation)
	roundTripper := oauth.NewOauthTransport(authService, skipSSLValidation)

	proxy := &httputil.ReverseProxy{
		Director:  oauth.RerouteRequest,
		Transport: roundTripper,
	}

	log.Fatal(http.ListenAndServe(":"+port, context.ClearHandler(proxy)))
}
