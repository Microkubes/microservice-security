package acl

import (
	"fmt"
	"net/http"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/ory/ladon"
)

// Configuration is the configuration for the ACL middleware.
type Configuration struct {
	// DBConfig is the configuration for the ACL database.
	DBConfig
}

// AccessContext is a map string => interface used for additional ACL context data for the ACL check.
type AccessContext map[string]interface{}

type contextKey string

var ladonWardenKey contextKey = "LadonWarden"

type RequestContext struct {
	Auth     *auth.Auth
	Action   string
	Subject  string
	Scopes   []string
	Resource string
	AccessContext
}

// NewACLMiddleware instantiates new SecurityChainMiddleware for ACL.
func NewACLMiddleware(manager ladon.Manager) (chain.SecurityChainMiddleware, error) {

	warden := ladon.Ladon{
		Manager: manager,
	}

	return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {

		authObj := auth.GetAuth(ctx)
		if authObj == nil {
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

		return context.WithValue(ctx, ladonWardenKey, warden), rw, warden.IsAllowed(&aclRequest)
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

// IsAllowed is a helper function that can be used inside a controller action to perform additional
// checks for ACL when the default check is not enough. An example is prtotecting a resoruce to be accessed
// only by its owner. The resource owner is not known until the resource is fetched from the database,
// and the resource is not fetched util the actual action executes. In this scenario we can use
// IsAllowed to check once we have the resource fetched from database.
func IsAllowed(ctx context.Context, req *http.Request, subject string, aclContext AccessContext) error {
	warden := ctx.Value(ladonWardenKey)

	if warden == nil {
		return fmt.Errorf("not ACL protected")
	}

	ladonWarden, ok := warden.(ladon.Warden)
	if !ok {
		return fmt.Errorf("warden is not ladon.Warden")
	}

	return ladonWarden.IsAllowed(toLadonRequest(req, subject, aclContext))
}

func CheckRequest(ctx context.Context, req *RequestContext) error {
	ladonReq := &ladon.Request{
		Action:   req.Action,
		Context:  ladon.Context{},
		Resource: req.Resource,
		Subject:  req.Subject,
	}
	cx := ladonReq.Context
	cx["userId"] = req.Auth.UserID
	cx["username"] = req.Auth.Username
	cx["roles"] = req.Auth.Roles
	cx["organizations"] = req.Auth.Organizations
	cx["scopes"] = req.Scopes

	warden, err := getLadonWarden(ctx)
	if err != nil {
		return err
	}
	if warden == nil {
		return fmt.Errorf("no ACL warden")
	}

	return warden.IsAllowed(ladonReq)
}

func getLadonWarden(ctx context.Context) (ladon.Warden, error) {
	warden := ctx.Value(ladonWardenKey)

	if warden == nil {
		return nil, nil
	}

	ladonWarden, ok := warden.(ladon.Warden)
	if !ok {
		return nil, fmt.Errorf("the warden is not ladon.Warden")
	}

	return ladonWarden, nil
}

func toLadonRequest(req *http.Request, subject string, aclCtx AccessContext) *ladon.Request {

	ladonCtx := ladon.Context{}

	for key, val := range aclCtx {
		ladonCtx[key] = val
	}

	return &ladon.Request{
		Action:   getAction(req),
		Resource: req.URL.Path,
		Subject:  subject,
		Context:  ladonCtx,
	}
}
