package oauth_test

import (
	"net/http"

	. "github.com/cfmobile/oauth2-route-service/oauth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Director", func() {
	var (
		req      *http.Request
		director *RouteServiceDirector
	)

	BeforeEach(func() {
		req, _ = http.NewRequest("GET", "http://sample.com", nil)
		director = &RouteServiceDirector{}
	})

	Context("Forward header set", func() {
		forwardUrl := "http://new-url.com"
		BeforeEach(func() {
			req.Header.Add("X-CF-Forwarded-Url", forwardUrl)
		})

		It("Sets the request URL to the forward url", func() {
			director.RerouteRequest(req)
			Expect(req.URL.String()).To(Equal(forwardUrl))
		})

		It("Sets the request Host to the forward url host", func() {
			director.RerouteRequest(req)
			Expect(req.Host).To(Equal("new-url.com"))
		})
	})

	Context("Keeps gorouter headers", func() {
		It("Keeps the signature and metadata headers", func() {
			req.Header.Add("X-CF-Proxy-Metadata", "some metadata")
			req.Header.Add("X-CF-Proxy-Signature", "some signature")

			director.RerouteRequest(req)

			Expect(req.Header.Get("X-CF-Proxy-Metadata")).To(Equal("some metadata"))
			Expect(req.Header.Get("X-CF-Proxy-Signature")).To(Equal("some signature"))
		})
	})
})
