<h1> Route Service for oauth2 using UAA</h1>

The following environment variables are required in order to run this app:

* UAA\_HOST: UAA Host (eg. https://uaa.my-cf.com )
* UAA\_LOGIN\_PATH: Path to the uaa login page (eg. /oauth/authorize )
* UAA\_LOGIN\_SCOPE: Login scopes required for this app, as defined in UAA and separated by '+' (eg. cloud_controller.read+openid )
* UAA\_CLIENT\_ID: Client id for the app using this route service, as defined in UAA (eg. dora-client )
* UAA\_CLIENT\_SECRET: Client secret for the app using this route service, as defined in UAA (eg. dora-secret )
* UAA\_REDIRECT\_PATH: Redirect path for the app, as defined in the UAA 'redirect\_uri' field. (eg. If redirect\_uri='https://dora.my-cf.com/oauth/callback' then UAA\_REDIRECT\_PATH should be /oauth/callback

<h2> Example usage </h2>

The following requires CF CLI version 6.16 or above.


Assuming I want to push a sample app called [dora](https://github.com/cloudfoundry/cf-acceptance-tests/tree/master/assets/dora)

<h3>1. Create an uaa client for dora</h3>

The easiest way is using the [cf-uaac gem](https://github.com/cloudfoundry/cf-uaac)

The client properties should be similar to below. Make sure to replace *my-cf.com* with a real cloudfoundry url. 
 

```
  dora-client
    scope: cloud_controller.read openid
    resource_ids: none
    authorized_grant_types: refresh_token client_credentials password authorization_code
    redirect_uri: https://dora.my-cf.com/oauth/callback
    autoapprove: true
    access_token_validity: 3600
    action: none
    authorities: scim.read
    signup_redirect_url:
    lastmodified: 1464810749000
```

<h3>2. Push the app without starting </h3>

`cf push dora --no-start`

<h3>3. Push the uaa route service. </h3>

The uaa oauth2 route service is written in go. The easiest way is to push it to cloud foundry as a binary app.

```
./cf-build.sh
cf push uaa-rs -b binary_buildpack --no-start
```

<h3>4. Set up the environment variables for the route service</h3>

```
cf set-env uaa-rs UAA_CLIENT_ID "dora-client"
cf set-env uaa-rs UAA_CLIENT_SECRET "dora-secret"
cf set-env uaa-rs UAA_HOST "https://uaa.my-cf.com"
cf set-env uaa-rs UAA_LOGIN_PATH "/oauth/authorize"
cf set-env uaa-rs UAA_LOGIN_SCOPE "cloud_controller.read+openid"
cf set-env uaa-rs UAA_REDIRECT_PATH "/oauth/callback"
```

<h3>5. Start the route service</h3>

``` cf start uaa-rs ```

<h3>6. Use the route service for dora </h3>

* Create a user provided service 
```cf create-user-provided-service my-uaa-rs -r https://uaa-rs.my-cf.com```

* Bind the route service to dora
```cf bind-route-service my-cf.com my-rs --hostname dora```

<h3>7. Start dora</h3>
``` cf start dora```

Dora should now require logging in before allowing access.
