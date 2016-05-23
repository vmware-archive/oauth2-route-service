package oauth_test

import (
	"net/http"

	. "github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/cfmobile/oauth2-route-service/oauth/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport", func() {
	var (
		transport       http.RoundTripper
		req             *http.Request
		fakeAuthService *fakes.FakeAuthService
	)

	BeforeEach(func() {

		fakeAuthService = &fakes.FakeAuthService{}
		req, _ = http.NewRequest("GET", "http://some-url.com", nil)
		transport = NewOauthTransport(fakeAuthService)
		req.Header.Add("X-CF-Forwarded-Url", "https://some-other-url.com")
		req.Header.Add("X-CF-Proxy-Metadata", "some metadata")
		req.Header.Add("X-CF-Proxy-Signature", "some signature")
	})

	Context("Missing gorouter headers", func() {
		It("returns an error response when there is no forward url", func() {
			req.Header.Del("X-CF-Forwarded-Url")

			res, err := transport.RoundTrip(req)
			Expect(res).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		It("returns an error response when there is no signature header", func() {
			req.Header.Del("X-CF-Proxy-Signature")

			res, err := transport.RoundTrip(req)
			Expect(res).To(BeNil())
			Expect(err).ToNot(BeNil())
		})

		It("returns an error response when there is no metadata header", func() {
			req.Header.Del("X-CF-Proxy-Metadata")

			res, err := transport.RoundTrip(req)
			Expect(res).To(BeNil())
			Expect(err).ToNot(BeNil())
		})
	})

	Context("gorouter headers present", func() {
		It("redirects to the login page if no access token is present", func() {
			loginResponse := &http.Response{
				StatusCode: http.StatusFound,
				Header:     make(http.Header),
			}

			loginResponse.Header.Set("Location", "http://some-login-page.com")
			fakeAuthService.CreateLoginRequiredResponseReturns(loginResponse, nil)
			fakeAuthService.IsUaaRedirectUrlReturns(true)

			res, err := transport.RoundTrip(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusFound))
			Expect(res.Header.Get("Location")).To(ContainSubstring("http://some-login-page.com"))
		})
	})

})
