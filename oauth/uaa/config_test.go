package uaa_test

import (
	"os"

	. "github.com/cfmobile/oauth2-route-service/oauth/uaa"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Context("Config parsing", func() {
		BeforeEach(func() {
			os.Setenv(UAA_HOST, "http://my-uaa-host.com")
			os.Setenv(UAA_LOGIN_PATH, "/oauth/authorize")
			os.Setenv(UAA_LOGIN_SCOPE, "scope1+scope2")

			os.Setenv(UAA_REDIRECT_PATH, "/auth/callback")

			os.Setenv(UAA_CLIENT_ID, "my-client-id")
			os.Setenv(UAA_CLIENT_SECRET, "my-client-secret")
		})

		testForMissingEnvProperty := func(property string) {
			os.Unsetenv(property)
			Expect(func() {
				GetConfigFromEnv()
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
				GetConfigFromEnv()
			}).ToNot(Panic())
		})

		It("sets the config properties to what the variables are set to", func() {
			config := GetConfigFromEnv()
			Expect(config.Host).To(Equal(os.Getenv(UAA_HOST)))
			Expect(config.LoginPath).To(Equal(os.Getenv(UAA_LOGIN_PATH)))
			Expect(config.LoginScope).To(Equal(os.Getenv(UAA_LOGIN_SCOPE)))
			Expect(config.RedirectPath).To(Equal(os.Getenv(UAA_REDIRECT_PATH)))
			Expect(config.ClientId).To(Equal(os.Getenv(UAA_CLIENT_ID)))
			Expect(config.ClientSecret).To(Equal(os.Getenv(UAA_CLIENT_SECRET)))
		})

	})

})
