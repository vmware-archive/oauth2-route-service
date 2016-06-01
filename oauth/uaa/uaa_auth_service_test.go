package uaa_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/cfmobile/oauth2-route-service/oauth"
	. "github.com/cfmobile/oauth2-route-service/oauth/uaa"
	"github.com/cfmobile/oauth2-route-service/oauth/uaa/fakes"
	"github.com/gorilla/sessions"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("UaaAuthService", func() {
	var (
		authService oauth.AuthService
		store       *fakes.FakeStore
	)

	BeforeEach(func() {
		os.Setenv(UAA_HOST, "http://my-uaa-host.com")
		os.Setenv(UAA_LOGIN_PATH, "/oauth/authorize")
		os.Setenv(UAA_LOGIN_SCOPE, "scope1+scope2")

		os.Setenv(UAA_REDIRECT_PATH, "/auth/callback")

		os.Setenv(UAA_CLIENT_ID, "my-client-id")
		os.Setenv(UAA_CLIENT_SECRET, "my-client-secret")

		store = &fakes.FakeStore{}
	})

	Context("Service creation", func() {
		testForMissingEnvProperty := func(property string) {
			os.Unsetenv(property)
			Expect(func() {
				NewAuthService(store)
			}).To(Panic())
		}

		It("panics if UAA_HOST is not set", func() {
			testForMissingEnvProperty(UAA_HOST)
		})

		It("panics if there is no UAA_REDIRECT_PATH", func() {
			testForMissingEnvProperty(UAA_REDIRECT_PATH)
		})

		It("panics if there is no UAA_LOGIN_PATH", func() {
			testForMissingEnvProperty(UAA_LOGIN_PATH)
		})

		It("panics if there is no UAA_LOGIN_SCOPE", func() {
			testForMissingEnvProperty(UAA_LOGIN_SCOPE)
		})

		It("panics if there is no UAA_CLIENT_ID", func() {
			testForMissingEnvProperty(UAA_CLIENT_ID)
		})

		It("panics if there is no UAA_CLIENT_SECRET", func() {
			testForMissingEnvProperty(UAA_CLIENT_SECRET)
		})

		It("succeeds if the env is set up properly", func() {
			Expect(func() {
				NewAuthService(store)
			}).ToNot(Panic())
		})
	})

	Context("Given proper environments setup", func() {
		BeforeEach(func() {
			authService = NewAuthService(store)
		})

		Context("IsUaaRedirectUrl", func() {
			It("checks that the request is from uaa", func() {
				req, _ := http.NewRequest("GET", "http://my-url.com/auth/callback", nil)
				Expect(authService.IsUaaRedirectUrl(req)).To(BeTrue())
			})

			It("returns false if the request is not from uaa", func() {
				req, _ := http.NewRequest("GET", "http://some-url.com/somepath", nil)
				Expect(authService.IsUaaRedirectUrl(req)).To(BeFalse())
			})
		})

		Context("CreateLoginRequiredResponse", func() {
			getLoginUrl := func() *url.URL {
				res, err := authService.CreateLoginRequiredResponse()
				Expect(err).To(BeNil())
				Expect(res.StatusCode).To(Equal(http.StatusFound))
				redirectURL, err := url.Parse(res.Header.Get("Location"))
				Expect(err).To(BeNil())
				return redirectURL
			}

			It("returns a response to redirect to the login page", func() {
				loginURL := getLoginUrl()
				Expect(loginURL.String()).To(ContainSubstring("http://my-uaa-host.com/oauth/authorize"))
			})

			It("sets the proper scopes", func() {
				loginURL := getLoginUrl()
				Expect(loginURL.Query().Get("scope")).To(Equal("scope1+scope2"))
			})

			It("sets the proper client id", func() {
				loginURL := getLoginUrl()
				Expect(loginURL.Query().Get("client_id")).To(Equal("my-client-id"))
			})

			It("will request a code response type", func() {
				loginURL := getLoginUrl()
				Expect(loginURL.Query().Get("response_type")).To(Equal("code"))
			})

			It("sets a cookie so save where the original navigation was aimed", func() {
				res, _ := authService.CreateLoginRequiredResponse()
				cookies := res.Cookies()
				fmt.Printf("%+v\n", cookies)
			})
		})

		Context("HasValidAuthHeaders", func() {
			var (
				uaaServer *ghttp.Server
				req       *http.Request
			)
			BeforeEach(func() {
				uaaServer = ghttp.NewServer()
				req, _ = http.NewRequest("GET", "http://my-app.com", nil)
				os.Setenv(UAA_HOST, uaaServer.URL())

				authService = NewAuthService(store)
			})

			It("returns false if there is an error", func() {
				store.GetReturns(&sessions.Session{}, errors.New("some error"))
				Expect(authService.HasValidAuthHeaders(req)).To(BeFalse())
			})

			It("returns false if there is no token", func() {
				store.GetReturns(&sessions.Session{}, nil)
				Expect(authService.HasValidAuthHeaders(req)).To(BeFalse())
			})

			Context("Given a token exists", func() {
				BeforeEach(func() {
					session := &sessions.Session{
						Values: make(map[interface{}]interface{}),
					}
					session.Values["token"] = "some-token"

					store.GetReturns(session, nil)
				})

				It("returns true if the uaa server returns 200", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/userinfo"),
							ghttp.VerifyHeaderKV("Authorization", "Bearer some-token"),
							ghttp.RespondWith(http.StatusOK, "all good"),
						),
					)
					Expect(authService.HasValidAuthHeaders(req)).To(BeTrue())
				})

				It("returns false if uaa is not able to verify the token", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.RespondWith(http.StatusForbidden, "no good"),
							ghttp.VerifyHeaderKV("Authorization", "Bearer some-token"),
						),
					)
					Expect(authService.HasValidAuthHeaders(req)).To(BeFalse())
				})
			})
		})

		Context("AddSessionCookie", func() {
			var (
				uaaServer        *ghttp.Server
				req              *http.Request
				res              *http.Response
				expectedSentData url.Values
			)

			BeforeEach(func() {
				uaaServer = ghttp.NewServer()
				req, _ = http.NewRequest("GET", "http://my-app.com/oauth/callback?code=mycode", nil)
				res = &http.Response{}

				os.Setenv(UAA_HOST, uaaServer.URL())

				authService = NewAuthService(store)

				expectedSentData = make(url.Values)
				expectedSentData.Set("grant_type", "authorization_code")
				expectedSentData.Set("code", "mycode")
				expectedSentData.Set("response_type", "token")
				// expectedSentData.Set("redirect_uri", "http://my-app.com/welcome")
			})

			verifyForm := func(w http.ResponseWriter, req *http.Request) {
				body, _ := ioutil.ReadAll(req.Body)
				Expect(string(body)).To(Equal(expectedSentData.Encode()))
			}

			It("returns an error if it can't get an auth token", func() {
				uaaServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/oauth/token"),
						ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
						verifyForm,
						ghttp.RespondWith(http.StatusInternalServerError, "error"),
					),
				)

				err := authService.AddSessionCookie(req, res)

				Expect(uaaServer.ReceivedRequests()).To(HaveLen(1))
				Expect(err).To(HaveOccurred())
			})

			Context("code is valid", func() {
				token := Token{
					AccessToken: "some-token",
					TokenType:   "bearer",
					ExpiresIn:   100,
				}

				BeforeEach(func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/oauth/token"),
							ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
							verifyForm,
							ghttp.RespondWithJSONEncoded(http.StatusOK, token),
						),
					)

					store.GetReturns(&sessions.Session{
						Values: make(map[interface{}]interface{}),
					}, nil)

					err := authService.AddSessionCookie(req, res)
					Expect(err).ToNot(HaveOccurred())
				})

				It("fetches an auth token from the uaa server", func() {
					Expect(uaaServer.ReceivedRequests()).To(HaveLen(1))
				})

				It("adds the access token to a the session", func() {
					expectedSession := sessions.Session{
						Values: make(map[interface{}]interface{}),
					}
					expectedSession.Values["token"] = token

					Expect(store.SaveCallCount()).To(Equal(1))
					callReq, _, callSession := store.SaveArgsForCall(1)
					Expect(callReq).To(Equal(req))
					Expect(callSession).To(Equal(expectedSession))
				})

				It("redirects the client after setting the session token", func() {
					Expect(res.StatusCode).To(Equal(http.StatusFound))
				})
			})
		})
	})
})
