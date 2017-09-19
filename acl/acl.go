package acl

import (
	"fmt"
	"net/http"

	"context"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/ory/ladon"
)

// Configuration is the configuration for the ACL middleware.
type Configuration struct {
	// DBConfig is the configuration for the ACL database.
	config.DBConfig
}

// NewACLMiddleware instantiates new SecurityChainMiddleware for ACL.
func NewACLMiddleware(conf *Configuration) (chain.SecurityChainMiddleware, error) {
	mongoManager, err := NewMongoDBLadonManager(&conf.DBConfig)
	if err != nil {
		return nil, err
	}

	warden := ladon.Ladon{
		Manager: mongoManager,
	}

	return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {

		authObj := auth.GetAuth(ctx)
		if authObj != nil {
			return ctx, rw, fmt.Errorf("No auth")
		}

		aclContext := ladon.Context{
			"roles":         authObj.Roles,
			"organizations": authObj.Organizations,
			"userId":        authObj.UserID,
			"username":      authObj.Username,
		}

		aclRequest := ladon.Request{
			Action:   getAction(req),
			Resource: req.URL.Path,
			Subject:  authObj.Username,
			Context:  aclContext,
		}

		return ctx, rw, warden.IsAllowed(&aclRequest)
	}, nil
}

// APIReadAction is "api:read". All HTTP methods except for POST, PUT and DELETE are considered to be "api:read" action.
const APIReadAction = "api:read"

// APIWriteAction is "api:write". HTTP methods POST, PUT and DELETE are considered "api:write" action.
const APIWriteAction = "api:write"

func getAction(req *http.Request) string {
	switch req.Method {
	case "POST":
		return APIWriteAction
	case "PUT":
		return APIWriteAction
	case "DELETE":
		return APIWriteAction
	default:
		return APIReadAction
	}
}
