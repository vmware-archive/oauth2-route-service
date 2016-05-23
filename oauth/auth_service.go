package oauth

import "net/http"

//go:generate counterfeiter . AuthService
type AuthService interface {
	IsUaaRedirectUrl(*http.Request) bool
	AddSessionCookie(uaaRedirectRequest *http.Request, res *http.Response) error
	HasValidAuthHeaders(*http.Request) bool
	CreateLoginRequiredResponse() (*http.Response, error)
}
