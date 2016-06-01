package uaa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/gorilla/sessions"
)

const (
	UAA_REDIRECT_PATH = "UAA_REDIRECT_PATH"

	UAA_CLIENT_ID     = "UAA_CLIENT_ID"
	UAA_CLIENT_SECRET = "UAA_CLIENT_SECRET"
	UAA_HOST          = "UAA_HOST"
	UAA_LOGIN_PATH    = "UAA_LOGIN_PATH"
	UAA_LOGIN_SCOPE   = "UAA_LOGIN_SCOPE"

	userInfoEndpoint = "/userinfo"
	tokenEndpoint    = "/oauth/token"
	sessionName      = "rs-session"
)

type UaaAuthService struct {
	uaaHost         string
	uaaRedirectPath string
	uaaLoginPath    string
	uaaLoginScope   string
	uaaClientId     string
	uaaClientSecret string
	store           sessions.Store
	client          *http.Client
}

func NewAuthService(store sessions.Store) oauth.AuthService {
	return &UaaAuthService{
		uaaHost:         parseEnvProperty(UAA_HOST),
		uaaRedirectPath: parseEnvProperty(UAA_REDIRECT_PATH),
		uaaLoginPath:    parseEnvProperty(UAA_LOGIN_PATH),
		uaaLoginScope:   parseEnvProperty(UAA_LOGIN_SCOPE),
		uaaClientId:     parseEnvProperty(UAA_CLIENT_ID),
		uaaClientSecret: parseEnvProperty(UAA_CLIENT_SECRET),
		store:           store,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
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
	code := req.URL.Query().Get("code")

	tokenRequest, err := u.createAuthTokenRequest(code)
	if err != nil {
		return err
	}
	tokenResponse, err := u.client.Do(tokenRequest)
	if err != nil {
		return err
	}
	if tokenResponse.StatusCode != http.StatusOK {
		return errors.New("Unable to get an auth token.")
	}

	var token Token
	body, err := ioutil.ReadAll(tokenResponse.Body)
	err = json.Unmarshal(body, &token)
	if err != nil {
		return err
	}

	session, _ := u.store.Get(req, sessionName)
	session.Values["token"] = token

	cw := newCookieWriter()
	err = u.store.Save(req, cw, session)
	if err != nil {
		return err
	}

	for key, headers := range cw.Header() {
		for _, header := range headers {
			res.Header.Add(key, header)
		}
	}

	return nil
}

func (u *UaaAuthService) createAuthTokenRequest(code string) (*http.Request, error) {
	requestBody := make(url.Values)
	requestBody.Set("grant_type", "authorization_code")
	requestBody.Set("code", code)
	requestBody.Set("response_type", "token")

	tokenRequest, err := http.NewRequest("POST", u.uaaHost+tokenEndpoint, strings.NewReader(requestBody.Encode()))
	if err != nil {
		return nil, err
	}
	tokenRequest.SetBasicAuth(u.uaaClientId, u.uaaClientSecret)

	return tokenRequest, err
}

func (u *UaaAuthService) HasValidAuthHeaders(req *http.Request) bool {
	session, err := u.store.Get(req, sessionName)
	if err != nil {
		return false
	}

	token, found := session.Values["token"]
	if !found {
		return false
	}

	tokenValue, ok := token.(string)
	if !ok {
		return false
	}

	return u.validateToken(tokenValue)
}

func (u *UaaAuthService) validateToken(token string) bool {
	userInfoAddr := u.uaaHost + userInfoEndpoint
	req, err := http.NewRequest("GET", userInfoAddr, nil)
	if err != nil {
		return false
	}

	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := u.client.Do(req)
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
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
