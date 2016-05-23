package oauth

import (
	"errors"
	"fmt"
	"net/http"
)

type OauthTransport struct {
	authService AuthService
}

func NewOauthTransport(authService AuthService) http.RoundTripper {
	return &OauthTransport{authService: authService}
}

// uaa redirect url? get access token
// access token present? check if valid. If it is forward to dashboard
// if not  go to login page
func (t *OauthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res := &http.Response{}

	err := checkHeaders(r)
	if err != nil {
		return nil, err
	}

	if t.authService.IsUaaRedirectUrl(r) {
		res, err := t.authService.CreateLoginRequiredResponse()
		if err != nil {
			return nil, err
		}
		return res, nil
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
