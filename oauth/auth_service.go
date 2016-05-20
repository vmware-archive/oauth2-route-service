package oauth

import "net/http"

type AuthService interface {
	IsUaaRedirectUrl(*http.Request) error
	AddSessionCookie(uaaRedirectRequest *http.Request, res *http.Response) error
	HasValidAuthHeaders(*http.Request) bool
	CreateLoginRequiredResponse() (*http.Response, error)
}
