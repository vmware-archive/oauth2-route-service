package oauth

import "net/http"

//go:generate counterfeiter . AuthService
type AuthService interface {
	IsUaaRedirectUrl(*http.Request) bool
	AuthenticatedAppRedirect(uaaRedirectRequest *http.Request) (*http.Response, error)
	HasValidAuthHeaders(*http.Request) bool
	CreateLoginRequiredResponse(*http.Request) (*http.Response, error)
}
