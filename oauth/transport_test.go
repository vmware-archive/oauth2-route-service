package oauth_test

import (
	"net/http"

	. "github.com/cfmobile/oauth2-route-service/oauth"
	"github.com/cfmobile/oauth2-route-service/oauth/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport", func() {
	Context("Missing forward url header", func() {
		var (
			transport http.RoundTripper
			req       *http.Request
		)

		BeforeEach(func() {
			transport = NewOauthTransport(&fakes.FakeAuthService{})
		})

		Context("Missing gorouter headers", func() {
			BeforeEach(func() {
				req, _ = http.NewRequest("GET", "http://some-url.com", nil)
				req.Header.Add("X-CF-Forwarded-Url", "https://some-other-url.com")
				req.Header.Add("X-CF-Proxy-Metadata", "some metadata")
				req.Header.Add("X-CF-Proxy-Signature", "some signature")
			})
			It("returns an error response when there is no forward url", func() {
				req.Header.Del("X-CF-Forwarded-Url")

				res, err := transport.RoundTrip(req)
				Expect(err).To(BeNil())
				Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			})

			It("returns an error response when there is no signature header", func() {
				req.Header.Del("X-CF-Proxy-Signature")

				res, err := transport.RoundTrip(req)
				Expect(err).To(BeNil())
				Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			})

			It("returns an error response when there is no metadata header", func() {
				req.Header.Del("X-CF-Proxy-Metadata")

				res, err := transport.RoundTrip(req)
				Expect(err).To(BeNil())
				Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
