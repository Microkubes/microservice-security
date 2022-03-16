package acl

import (
	"net/http"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/k0kubun/pp"
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
			pp.Println("the auth obj ", authObj)
			aclContext := ladon.Context{
				"roles":         authObj.Roles,
				"organizations": authObj.Organizations,
				"userId":        authObj.UserID,
				"username":      authObj.Username,
			}
			aclRequest := ladon.Request{
				Action:   getAction(c.Request()),
				Resource: c.Request().URL.Path,
				Subject:  authObj.Username,
				Context:  aclContext,
			}
			pp.Println("THE ACL REQ ", aclRequest)
			pp.Println("THE WARDEN RES ", warden.IsAllowed(&aclRequest))
			if err := warden.IsAllowed(&aclRequest); err != nil {
				return c.JSON(403, "you don't have permissions to execute this action")
			}
			return nil
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
