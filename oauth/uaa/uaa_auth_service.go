package uaa

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
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

	userInfoEndpoint   = "/userinfo"
	tokenEndpoint      = "/oauth/token"
	sessionName        = "rs-session"
	redirectCookieName = "X-RS-Redirect-URL"
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
	gob.Register(Token{})
	return &UaaAuthService{
		uaaHost:         parseEnvProperty(UAA_HOST),
		uaaRedirectPath: parseEnvProperty(UAA_REDIRECT_PATH),
		uaaLoginPath:    parseEnvProperty(UAA_LOGIN_PATH),
		uaaLoginScope:   parseEnvProperty(UAA_LOGIN_SCOPE),
		uaaClientId:     parseEnvProperty(UAA_CLIENT_ID),
		uaaClientSecret: parseEnvProperty(UAA_CLIENT_SECRET),
		store:           store,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
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

func (u *UaaAuthService) AuthenticatedAppRedirect(req *http.Request) (*http.Response, error) {
	code := req.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("Expected an authentication code but didn't get one.")
	}

	token, err := u.getAuthToken(code)
	if err != nil {
		return nil, err
	}

	res := &http.Response{
		Header: make(http.Header),
		Body:   ioutil.NopCloser(bytes.NewReader([]byte{})),
	}

	err = u.addTokenToCookie(req, res, token)
	if err != nil {
		return nil, err
	}

	redirectCookie, err := req.Cookie(redirectCookieName)
	if err != nil {
		return nil, err
	}
	res.StatusCode = http.StatusFound
	res.Header.Set("Location", redirectCookie.Value)

	return res, nil
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
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return tokenRequest, err
}

func (u *UaaAuthService) getAuthToken(code string) (*Token, error) {
	tokenRequest, err := u.createAuthTokenRequest(code)
	if err != nil {
		return nil, err
	}
	tokenResponse, err := u.client.Do(tokenRequest)
	if err != nil {
		return nil, err
	}
	if tokenResponse.StatusCode != http.StatusOK {
		log.Printf("Unable to get a token: %+v\n", tokenResponse)
		log.Printf("Token Request: %+v\n", tokenRequest)
		return nil, errors.New("Unable to get an auth token.")
	}

	var token Token
	body, err := ioutil.ReadAll(tokenResponse.Body)
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (u *UaaAuthService) addTokenToCookie(req *http.Request, res *http.Response, token *Token) error {
	session, err := u.store.Get(req, sessionName)
	session.Values["token"] = *token

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

func (u *UaaAuthService) HasValidAuthHeaders(req *http.Request) bool {
	session, err := u.store.Get(req, sessionName)
	if err != nil {
		return false
	}

	token, found := session.Values["token"]
	if !found {
		log.Println("Unable to find a token")
		return false
	}

	tokenValue, ok := token.(Token)
	if !ok {
		return false
	}

	log.Println("Found token " + tokenValue.AccessToken)
	return u.validateToken(tokenValue.AccessToken)
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

func (u *UaaAuthService) CreateLoginRequiredResponse(req *http.Request) (*http.Response, error) {
	loginResponse := &http.Response{
		StatusCode: http.StatusFound,
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
	}

	loginUrl, err := url.Parse(u.uaaHost + u.uaaLoginPath)
	if err != nil {
		return nil, err
	}
	loginQuery := u.createLoginQuery()
	loginUrl.RawQuery = loginQuery.Encode()

	loginResponse.Header.Set("Location", loginUrl.String())

	cookie := getRedirectCookie(req.URL)
	loginResponse.Header.Add("Set-Cookie", cookie.String())

	return loginResponse, nil
}

func (u *UaaAuthService) createLoginQuery() url.Values {
	queryValues := make(url.Values)

	queryValues.Set("scope", u.uaaLoginScope)
	queryValues.Set("client_id", u.uaaClientId)
	queryValues.Set("response_type", "code")

	return queryValues
}

func getRedirectCookie(url *url.URL) *http.Cookie {
	cookie := &http.Cookie{
		Name:  "X-RS-Redirect-URL",
		Value: url.String(),
	}
	return cookie
}
