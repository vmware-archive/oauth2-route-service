package main

import "os"

const (
	DEFAULT_PORT = "8080"
)

func main() {
	var port string

	if port = os.Getenv("PORT"); len(port) == 0 {
		port = DEFAULT_PORT
	}
}
