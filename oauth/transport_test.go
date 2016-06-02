package oauth_test

import (
	"errors"
	"io/ioutil"
	"net/http"

	. "github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/cfmobile/oauth2-route-service/oauth/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Transport", func() {
	var (
		transport       http.RoundTripper
		req             *http.Request
		fakeAuthService *fakes.FakeAuthService
		dashboardServer *ghttp.Server
	)

	BeforeEach(func() {
		fakeAuthService = &fakes.FakeAuthService{}
		dashboardServer = ghttp.NewServer()
		dashboardServer.AppendHandlers(ghttp.RespondWith(200, []byte("Some response")))

		req, _ = http.NewRequest("GET", dashboardServer.URL(), nil)
		transport = NewOauthTransport(fakeAuthService, true)
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
		var loginResponse *http.Response
		BeforeEach(func() {
			loginResponse = &http.Response{
				StatusCode: http.StatusFound,
				Header:     make(http.Header),
			}

			loginResponse.Header.Set("Location", "http://some-login-page.com")
		})

		It("redirects to the login page if the access token is not valid", func() {
			fakeAuthService.CreateLoginRequiredResponseReturns(loginResponse, nil)
			fakeAuthService.HasValidAuthHeadersReturns(false)

			res, err := transport.RoundTrip(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusFound))
			Expect(res.Header.Get("Location")).To(ContainSubstring("http://some-login-page.com"))
			Expect(dashboardServer.ReceivedRequests()).To(HaveLen(0))
		})

		It("returns an error if it can't get an access token from the access code", func() {
			fakeAuthService.IsUaaRedirectUrlReturns(true)
			fakeAuthService.AuthenticatedAppRedirectReturns(nil, errors.New("some error"))

			res, err := transport.RoundTrip(req)
			Expect(err).ToNot(BeNil())
			Expect(res).To(BeNil())
			Expect(dashboardServer.ReceivedRequests()).To(HaveLen(0))
		})

		It("forwards the request to the dashboard uf the auth token is valid", func() {
			fakeAuthService.IsUaaRedirectUrlReturns(false)
			fakeAuthService.HasValidAuthHeadersReturns(true)

			res, err := transport.RoundTrip(req)
			Expect(dashboardServer.ReceivedRequests()).To(HaveLen(1))
			Expect(err).To(BeNil())
			Expect(res).ToNot(BeNil())
			body, _ := ioutil.ReadAll(res.Body)
			Expect(body).To(Equal([]byte("Some response")))
		})
	})
})
