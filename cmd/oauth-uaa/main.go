package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/cfmobile/oauth2-route-service/oauth/uaa"
	"github.com/gorilla/sessions"
)

const (
	DEFAULT_PORT = "8080"
)

func main() {
	var port string

	if port = os.Getenv("PORT"); len(port) == 0 {
		port = DEFAULT_PORT
	}

	store := sessions.NewCookieStore([]byte("so-secret"))
	authService := uaa.NewAuthService(store)
	roundTripper := oauth.NewOauthTransport(authService)

	proxy := &httputil.ReverseProxy{
		Director:  oauth.RerouteRequest,
		Transport: roundTripper,
	}

	log.Fatal(http.ListenAndServe(":"+port, proxy))
}
