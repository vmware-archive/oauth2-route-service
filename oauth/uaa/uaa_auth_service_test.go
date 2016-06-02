package uaa_test

import (
	"errors"
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
				NewAuthService(store, true)
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
				NewAuthService(store, true)
			}).ToNot(Panic())
		})
	})

	Context("Given proper environments setup", func() {
		BeforeEach(func() {
			authService = NewAuthService(store, true)
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
			var req *http.Request

			getLoginUrl := func(req *http.Request) *url.URL {
				res, err := authService.CreateLoginRequiredResponse(req)
				Expect(err).To(BeNil())
				Expect(res.StatusCode).To(Equal(http.StatusFound))
				redirectURL, err := url.Parse(res.Header.Get("Location"))
				Expect(err).To(BeNil())
				return redirectURL
			}

			BeforeEach(func() {
				req, _ = http.NewRequest("GET", "http://my-app.com/start-page", nil)
			})

			It("returns a response to redirect to the login page", func() {
				loginURL := getLoginUrl(req)
				Expect(loginURL.String()).To(ContainSubstring("http://my-uaa-host.com/oauth/authorize"))
			})

			It("sets the proper scopes", func() {
				loginURL := getLoginUrl(req)
				Expect(loginURL.Query().Get("scope")).To(Equal("scope1+scope2"))
			})

			It("sets the proper client id", func() {
				loginURL := getLoginUrl(req)
				Expect(loginURL.Query().Get("client_id")).To(Equal("my-client-id"))
			})

			It("will request a code response type", func() {
				loginURL := getLoginUrl(req)
				Expect(loginURL.Query().Get("response_type")).To(Equal("code"))
			})

			It("sets a cookie so save where the original navigation was directed", func() {
				res, _ := authService.CreateLoginRequiredResponse(req)
				cookies := res.Cookies()
				Expect(cookies).To(HaveLen(1))
				Expect(cookies[0].Name).To(Equal("X-RS-Redirect-URL"))
				Expect(cookies[0].Value).To(Equal("http://my-app.com/start-page"))
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

				authService = NewAuthService(store, true)
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
					session.Values["token"] = Token{AccessToken: "some-token"}

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

		Context("AuthenticatedAppRedirect", func() {
			var (
				uaaServer        *ghttp.Server
				req              *http.Request
				expectedSentData url.Values
			)

			BeforeEach(func() {
				uaaServer = ghttp.NewServer()

				os.Setenv(UAA_HOST, uaaServer.URL())

				authService = NewAuthService(store, true)

				expectedSentData = make(url.Values)
				expectedSentData.Set("grant_type", "authorization_code")
				expectedSentData.Set("code", "my-code")
				expectedSentData.Set("response_type", "token")
			})

			verifyForm := func(w http.ResponseWriter, req *http.Request) {
				body, _ := ioutil.ReadAll(req.Body)
				Expect(string(body)).To(Equal(expectedSentData.Encode()))
			}

			It("returns an error if it doesn't have an auth code", func() {
				req, _ = http.NewRequest("GET", "http://my-app.com/oauth/callback", nil)
				res, err := authService.AuthenticatedAppRedirect(req)

				Expect(err).To(HaveOccurred())
				Expect(res).To(BeNil())
				Expect(uaaServer.ReceivedRequests()).To(HaveLen(0))
			})

			It("returns an error if the auth code is not valid", func() {
				req, _ = http.NewRequest("GET", "http://my-app.com/oauth/callback?code=my-code", nil)

				uaaServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/oauth/token"),
						ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
						verifyForm,
						ghttp.RespondWith(http.StatusInternalServerError, "error"),
					),
				)

				res, err := authService.AuthenticatedAppRedirect(req)

				Expect(uaaServer.ReceivedRequests()).To(HaveLen(1))
				Expect(err).To(HaveOccurred())
				Expect(res).To(BeNil())
			})

			Context("auth code is valid", func() {
				token := Token{
					AccessToken: "some-token",
					TokenType:   "bearer",
					ExpiresIn:   100,
				}

				BeforeEach(func() {
					req, _ = http.NewRequest("GET", "http://my-app.com/oauth/callback?code=my-code", nil)
					req.AddCookie(&http.Cookie{Name: "X-RS-Redirect-URL", Value: "http://my-app.com/start-page"})

					store.GetReturns(&sessions.Session{
						Values: make(map[interface{}]interface{}),
					}, nil)

				})

				It("returns an error if it can't parse the token response", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/oauth/token"),
							ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
							verifyForm,
							ghttp.RespondWith(http.StatusOK, "bad data"),
						),
					)

					res, err := authService.AuthenticatedAppRedirect(req)
					Expect(err).To(HaveOccurred())
					Expect(res).To(BeNil())
				})

				It("fetches an auth token from the uaa server", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/oauth/token"),
							ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
							verifyForm,
							ghttp.RespondWithJSONEncoded(http.StatusOK, token),
						),
					)

					_, err := authService.AuthenticatedAppRedirect(req)
					Expect(err).NotTo(HaveOccurred())
					Expect(uaaServer.ReceivedRequests()).To(HaveLen(1))
				})

				It("adds the access token to the session", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/oauth/token"),
							ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
							verifyForm,
							ghttp.RespondWithJSONEncoded(http.StatusOK, token),
						),
					)

					expectedSession := &sessions.Session{
						Values: make(map[interface{}]interface{}),
					}
					expectedSession.Values["token"] = token

					_, err := authService.AuthenticatedAppRedirect(req)
					Expect(err).NotTo(HaveOccurred())

					Expect(store.SaveCallCount()).To(Equal(1))
					callReq, _, callSession := store.SaveArgsForCall(0)
					Expect(callReq).To(Equal(req))
					Expect(callSession).To(Equal(expectedSession))
				})

				It("redirects the client to the original destination", func() {
					uaaServer.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/oauth/token"),
							ghttp.VerifyBasicAuth(os.Getenv(UAA_CLIENT_ID), os.Getenv(UAA_CLIENT_SECRET)),
							verifyForm,
							ghttp.RespondWithJSONEncoded(http.StatusOK, token),
						),
					)
					res, err := authService.AuthenticatedAppRedirect(req)
					Expect(err).NotTo(HaveOccurred())

					Expect(res.StatusCode).To(Equal(http.StatusFound))
					Expect(res.Header.Get("Location")).To(Equal("http://my-app.com/start-page"))
				})
			})
		})
	})
})
