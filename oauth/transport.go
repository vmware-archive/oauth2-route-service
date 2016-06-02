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

func NewOauthTransport(authService AuthService, skipSSLValidation bool) http.RoundTripper {
	return &OauthTransport{
		authService: authService,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipSSLValidation},
		},
	}
}

func (t *OauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	err := checkHeaders(req)
	if err != nil {
		log.Printf("Invalid headers. %+v\n", req.Header)
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
		res, err := t.authService.CreateLoginRequiredResponse(req)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}
		return res, nil
	}

	res, err := t.transport.RoundTrip(req)
	if err != nil {
		log.Println(err.Error())
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
