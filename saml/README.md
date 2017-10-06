SAML Security
============

This package contains functions and types for enabling SAML as a security mechanism
in a microservice.

# Setting up a SAML security

There are a couple of things you need to do to enable the SAML security middleware.
For details on SAML you can find many resources on the official site: http://saml.xml.org/.

## Setting up the secret keys

Service providers should use the same saml keys as SAML IdP.

In order to create them create a directory in which you'll keep your key-pair:

```bash
mkdir saml-keys
cd saml-keys
```

Each service provider must have an self-signed X.509 key pair established. You can generate your own with something like this:

```bash
openssl req -x509 -newkey rsa:2048 -keyout service.key -out service.cert -days 365 -nodes -subj "/CN=myservice.example.com"
```

**NOTE:** Make sure you have service.key and service.cert files in the saml-keys directory

## Set up SAML in Goa

Create a security file app/security.go with the following content:

```go
package app

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
)

// NewSAMLSecurity creates a SAML security definition.
func NewSAMLSecurityMiddleware(cert, key string) *samlsp.Middleware {
	keyPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	gatewayURL := os.Getenv("API_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "https://localhost:8082"
	}

	rootURL, err := url.Parse(fmt.Sprintf("%s/user-profile", gatewayURL))
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse(fmt.Sprintf("%s/saml/idp/metadata", gatewayURL))
	if err != nil {
		panic(err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		IDPMetadataURL: idpMetadataURL,
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
	})

	return samlSP
}
```

In the config.json file map of URLs for the internal services:
```
{
	other config info here,
 	"services": {
		"microservice-registration": "https://localhost:8083/users",
		"microservice-user": "http://localhost:8081/users"
	}
}
```

In order to use Google as IdP you must use https over http. More details: 
* Golang https: https://gist.github.com/denji/12b3a568f092ab951456

More details on how to configure the SAML security are available on the following
site:
 * Example: https://github.com/crewjam/saml

## Setting up a SecurityChain

You need to set up a security chain for the microservice.

In the ```main.go``` file of your microservice, set up the SAML Security Chain
middleware and add it to the security chain.

```go

import (
	"github.com/JormungandrK/microservice-security/saml"
	"github.com/JormungandrK/microservice-security/chain"
)

func main() {
	// Create new SAML security chain
  	// "saml-keys" is the directory containing the keys
  	spMiddleware := app.NewSAMLSecurityMiddleware("saml-keys/service.cert", "saml-keys/service.key")
	SAMLMiddleware := saml.NewSAMLSecurity(spMiddleware)
	sc := chain.NewSecurityChain().AddMiddleware(SAMLMiddleware)

    // other initializations here...

    service.Use(chain.AsGoaMiddleware(sc)) // attach the security chain as Goa middleware

	// Send SP Metadata to the SAML IdP
	unregisterSP, err := saml.RegisterSP(spMiddleware)
	if err != nil {
		service.LogError("setupSAML", "err", err)
		return
	}
	defer unregisterSP()
}

```

# Testing the setup

To test the setup, you'll need to generate and sign a JWT token.

Example of the JWT token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODIvc2FtbC9tZXRhZGF0YSIsImF0dHIiO
nsib3JnYW5pemF0aW9ucyI6Ik96cmcxLCBPcmcyIiwicm9sZXMiOiJ1c2VyLCBhZG1pbiIsInVzZXJJZCI6IjU5YTAwNmFlMDAwMDAwMDA
wMDAwMDAwMCIsInVzZXJuYW1lIjoidGVzdC11c2VyIn19.vLl5hWsbYDSybhokeA4sFKJnZznesiUje5tzsCYZzl4
```

(Note that the JWT is actually one line. For readability purposes it is displayed here
  in multiple lines.)

Then you will need to set up the cookie named "saml_token":
```bash
 curl -v -b "saml_token=eyJhbGciO...<full token here>...zsCYZzl4" http://localhost:8082/profiles/me
``` 
