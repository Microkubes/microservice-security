package acl

import (
	"fmt"
	"net/http"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/labstack/echo/v4"
	"github.com/ory/ladon"
)

const (
	APIReadAction  = "api:read"
	APIWriteAction = "api:write"
)

// Configuration is the configuration for the ACL middleware.
type Configuration struct {
	// DBConfig is the configuration for the ACL database
	config.DBConfig
}

// AccessContext is a map string => interface used for additional ACL context data for the ACL check.
type AccessContext map[string]interface{}

// TODO: write a detailed comment
func NewACLMiddleware(manager ladon.Manager) (chain.EchoMiddleware, error) {
	warden := ladon.Ladon{
		Manager: manager,
	}
	aclMiddleware := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authObj := c.Get("userInfo").(*auth.Auth)
			if authObj == nil {
				return c.JSON(400, "auth object is missing")
			}
			aclContext := ladon.Context{
				"roles":         authObj.Roles,
				"organizations": authObj.Organizations,
				"userId":        authObj.UserID,
				"username":      authObj.Username,
			}
			apiPrefix := c.Get("restApiPrefix")
			serviceName := c.Get("serviceName")
			resourcePath := fmt.Sprintf("/%s/%s%s", apiPrefix, serviceName, c.Path())
			fmt.Println("the resource path ", resourcePath)
			aclRequest := ladon.Request{
				Action:   getAction(c.Request()),
				Resource: resourcePath,
				Subject:  authObj.Username,
				Context:  aclContext,
			}
			if err := warden.IsAllowed(&aclRequest); err != nil {
				return c.JSON(403, err)
			}
			return next(c)
		}
	}
	return aclMiddleware, nil
}

func getAction(req *http.Request) string {
	switch req.Method {
	case "POST":
		return APIWriteAction
	case "PUT":
		return APIWriteAction
	case "PATCH":
		return APIWriteAction
	case "DELETE":
		return APIWriteAction
	default:
		return APIReadAction
	}
}
