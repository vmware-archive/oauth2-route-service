package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

const (
	UAA_REDIRECT_PATH = "UAA_REDIRECT_PATH"

	UAA_CLIENT_ID   = "UAA_CLIENT_ID"
	UAA_HOST        = "UAA_HOST"
	UAA_LOGIN_PATH  = "UAA_LOGIN_PATH"
	UAA_LOGIN_SCOPE = "UAA_LOGIN_SCOPE"
)

type UaaAuthService struct {
	uaaHost         string
	uaaRedirectPath string
	uaaLoginPath    string
	uaaLoginScope   string
	uaaClientId     string
}

func NewAuthService() AuthService {
	return &UaaAuthService{
		uaaHost:         parseEnvProperty(UAA_HOST),
		uaaRedirectPath: parseEnvProperty(UAA_REDIRECT_PATH),
		uaaLoginPath:    parseEnvProperty(UAA_LOGIN_PATH),
		uaaLoginScope:   parseEnvProperty(UAA_LOGIN_SCOPE),
		uaaClientId:     parseEnvProperty(UAA_CLIENT_ID),
	}
}

func parseEnvProperty(property string) string {
	value := os.Getenv(property)
	if value == "" {
		panic(fmt.Sprintf("%s needs to be set", property))
	}
	return value
}

func (u *UaaAuthService) IsUaaRedirectUrl(req *http.Request) bool {
	return req.URL.Path == u.uaaRedirectPath
}

func (u *UaaAuthService) AddSessionCookie(req *http.Request, res *http.Response) error {
	return nil
}

func (u *UaaAuthService) HasValidAuthHeaders(req *http.Request) bool {
	return false
}

func (u *UaaAuthService) CreateLoginRequiredResponse() (*http.Response, error) {
	loginResponse := &http.Response{
		StatusCode: http.StatusFound,
		Header:     make(http.Header),
	}

	loginUrl, err := url.Parse(u.uaaHost + u.uaaLoginPath)
	if err != nil {
		return nil, err
	}
	loginQuery := u.createLoginQuery()
	loginUrl.RawQuery = loginQuery.Encode()

	loginResponse.Header.Set("Location", loginUrl.String())
	return loginResponse, nil
}

func (u *UaaAuthService) createLoginQuery() url.Values {
	queryValues := make(url.Values)

	queryValues.Set("scope", u.uaaLoginScope)
	queryValues.Set("client_id", u.uaaClientId)
	queryValues.Set("response_type", "code")

	return queryValues
}
