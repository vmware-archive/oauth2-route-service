package oauth_test

import (
	"net/http"
	"net/url"
	"os"

	. "github.com/cfmobile/oauth2-route-service/oauth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("UaaAuthService", func() {
	var (
		authService AuthService
	)

	BeforeEach(func() {
		os.Setenv(UAA_HOST, "http://my-uaa-host.com")
		os.Setenv(UAA_LOGIN_PATH, "/oauth/authorize")
		os.Setenv(UAA_LOGIN_SCOPE, "scope1+scope2")

		os.Setenv(UAA_REDIRECT_PATH, "/auth/callback")

		os.Setenv(UAA_CLIENT_ID, "my-client-id")
	})

	Context("Service creation", func() {
		testForMissingEnvProperty := func(property string) {
			os.Unsetenv(property)
			Expect(func() {
				NewAuthService()
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

		It("succeeds if the env is set up properly", func() {
			Expect(func() {
				NewAuthService()
			}).ToNot(Panic())
		})
	})

	Context("Given proper environments setup", func() {
		BeforeEach(func() {
			authService = NewAuthService()
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
		})
	})
})
