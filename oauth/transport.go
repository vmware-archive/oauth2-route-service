package oauth

import "net/http"

type OauthTransport struct {
	authService AuthService
}

func NewOauthTransport(authService AuthService) http.RoundTripper {
	return &OauthTransport{authService: authService}
}

func (t *OauthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, nil
}
