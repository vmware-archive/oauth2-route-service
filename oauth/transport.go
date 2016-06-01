package oauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type OauthTransport struct {
	authService AuthService
	transport   http.RoundTripper
}

func NewOauthTransport(authService AuthService) http.RoundTripper {
	return &OauthTransport{
		authService: authService,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// uaa redirect url? get access token
// access token present? check if valid. If it is forward to dashboard
// if not  go to login page
func (t *OauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Println("Received a new request to route")
	fmt.Printf("Request: %+v\n", req)
	err := checkHeaders(req)
	if err != nil {
		log.Printf("Bad headers. %+v\n", req.Header)
		return nil, err
	}

	if t.authService.IsUaaRedirectUrl(req) {
		res, err := t.authService.AuthenticatedAppRedirect(req)
		if err != nil {
			return nil, err
		}
		return res, nil
	}

	if !t.authService.HasValidAuthHeaders(req) {
		fmt.Printf("No auth header, redirect to ogin url\n")
		res, err := t.authService.CreateLoginRequiredResponse(req)
		fmt.Printf("Login response: %+v\n", res)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}
		return res, nil
	}

	res, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func checkHeaders(r *http.Request) error {
	if r.Header.Get(RouteServiceForwardHeader) == "" {
		return missingHeaderError(RouteServiceForwardHeader)
	}
	if r.Header.Get(RouteServiceSignatureHeader) == "" {
		return missingHeaderError(RouteServiceSignatureHeader)
	}
	if r.Header.Get(RouteServiceMetadataHeader) == "" {
		return missingHeaderError(RouteServiceMetadataHeader)
	}
	return nil
}

func missingHeaderError(header string) error {
	return errors.New(fmt.Sprintf("Missing expected header: %s", header))
}
