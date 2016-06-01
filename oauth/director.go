package oauth

import (
	"log"
	"net/http"
	"net/url"
)

const (
	RouteServiceForwardHeader   = "X-CF-Forwarded-Url"
	RouteServiceSignatureHeader = "X-CF-Proxy-Signature"
	RouteServiceMetadataHeader  = "X-CF-Proxy-Metadata"
)

func RerouteRequest(req *http.Request) {
	forwardedUrlString := req.Header.Get(RouteServiceForwardHeader)

	forwardedUrl, err := url.Parse(forwardedUrlString)
	if err != nil {
		log.Printf("Request %+v does not have a forward url.\n", req)
		return
	}

	req.URL = forwardedUrl
	req.Host = forwardedUrl.Host
}
