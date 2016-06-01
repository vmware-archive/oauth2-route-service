package uaa

import "net/http"

type cookieWriter struct {
	header http.Header
}

func newCookieWriter() *cookieWriter {
	return &cookieWriter{header: make(http.Header)}
}

func (c *cookieWriter) Header() http.Header {
	return c.header
}

func (c *cookieWriter) Write([]byte) (int, error) {
	//noop
	return 0, nil
}

func (c *cookieWriter) WriteHeader(int) {
	//noop
}
