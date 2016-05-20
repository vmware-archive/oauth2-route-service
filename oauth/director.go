package oauth

import (
	"log"
	"net/http"
	"net/url"
)

type RouteServiceDirector struct {
}

const (
	RouteServiceForwardHeader = "X-CF-Forwarded-Url"
)

func (d *RouteServiceDirector) RerouteRequest(r *http.Request) {
	forwardedUrlString := r.Header.Get(RouteServiceForwardHeader)

	forwardedUrl, err := url.Parse(forwardedUrlString)
	if err != nil {
		log.Printf("Request %+v does not have a forward url.\n", r)
		return
	}

	r.URL = forwardedUrl
	r.Host = forwardedUrl.Host
}
