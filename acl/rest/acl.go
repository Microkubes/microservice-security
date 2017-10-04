package rest

import (
	"github.com/JormungandrK/microservice-security/acl/rest/app"
	"github.com/goadesign/goa"
)

// AclController implements the acl resource.
type AclController struct {
	*goa.Controller
}

// NewAclController creates a acl controller.
func NewAclController(service *goa.Service) *AclController {
	return &AclController{Controller: service.NewController("AclController")}
}

// Get runs the get action.
func (c *AclController) Get(ctx *app.GetAclContext) error {
	// AclController_Get: start_implement

	// Put your logic here

	// AclController_Get: end_implement
	return nil
}
