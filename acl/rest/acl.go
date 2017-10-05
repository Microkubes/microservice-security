package rest

import (
	"fmt"

	"github.com/JormungandrK/microservice-security/acl"
	"github.com/JormungandrK/microservice-security/acl/rest/app"
	"github.com/goadesign/goa"
	"github.com/ory/ladon"
	uuid "github.com/satori/go.uuid"
)

// AclController implements the acl resource.
type AclController struct {
	*goa.Controller
	ladon.Manager
}

// NewAclController creates a acl controller.
func NewAclController(service *goa.Service, manager ladon.Manager) *AclController {
	return &AclController{
		Controller: service.NewController("AclController"),
		Manager:    manager,
	}
}

// CreatePolicy runs the createPolicy action.
func (c *AclController) CreatePolicy(ctx *app.CreatePolicyAclContext) error {
	// AclController_CreatePolicy: start_implement

	description := ""
	if ctx.Payload.Description != nil {
		description = *ctx.Payload.Description
	}
	var id string
	if ctx.Payload.ID != nil && *ctx.Payload.ID != "" {
		id = *ctx.Payload.ID
	} else {
		id = uuid.NewV4().String()
	}

	if ctx.Payload.Actions == nil || len(ctx.Payload.Actions) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one action is required"))
	}

	if ctx.Payload.Resources == nil || len(ctx.Payload.Resources) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one resource is required"))
	}

	if ctx.Payload.Subjects == nil || len(ctx.Payload.Subjects) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one subject is required"))
	}

	aclPolicy := &ladon.DefaultPolicy{
		Actions:     ctx.Payload.Actions,
		Description: description,
		Effect:      ctx.Payload.Effect,
		ID:          id,
		Resources:   ctx.Payload.Resources,
		Subjects:    ctx.Payload.Subjects,
		Conditions:  ladon.Conditions{},
	}

	if ctx.Payload.Conditions != nil {

		for _, condDef := range ctx.Payload.Conditions {
			if condDef.Patterns == nil || len(condDef.Patterns) == 0 {
				return ctx.BadRequest(fmt.Errorf("must specify at least one pattern for the condition"))
			}
			cond, err := acl.NewCondition(condDef.Type, condDef.Patterns)
			if err != nil {
				return ctx.BadRequest(err)
			}
			aclPolicy.Conditions[condDef.Name] = cond
		}
	}

	existingACL, err := c.Manager.Get(id)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if existingACL != nil {
		return ctx.BadRequest(fmt.Errorf("policy already exists"))
	}

	err = c.Manager.Create(aclPolicy)
	if err != nil {
		return ctx.InternalServerError(err)
	}

	// AclController_CreatePolicy: end_implement
	return ctx.Created(toACLPolicyMedia(aclPolicy))
}

func toACLPolicyMedia(p *ladon.DefaultPolicy) *app.ACLPolicy {
	ap := &app.ACLPolicy{
		Actions:     p.Actions,
		Description: &p.Description,
		Effect:      &p.Effect,
		ID:          &p.ID,
		Resources:   p.Resources,
		Subjects:    p.Subjects,
		Conditions:  []*app.Condition{},
	}
	for cName, cond := range p.Conditions {
		allowedPatternsCond, ok := cond.(*acl.AllowedPatternsCondition)
		if ok {
			c := &app.Condition{
				Name:     cName,
				Type:     allowedPatternsCond.Name,
				Patterns: allowedPatternsCond.Values,
			}
			ap.Conditions = append(ap.Conditions, c)
		}
	}
	return ap
}

// DeletePolicy runs the deletePolicy action.
func (c *AclController) DeletePolicy(ctx *app.DeletePolicyAclContext) error {
	// AclController_DeletePolicy: start_implement
	policy, err := c.Manager.Get(ctx.PolicyID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if policy == nil {
		return ctx.NotFound(fmt.Errorf("not-found"))
	}

	err = c.Manager.Delete(ctx.PolicyID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	// AclController_DeletePolicy: end_implement
	id := policy.GetID()
	res := &app.ACLPolicy{
		ID: &id,
	}
	return ctx.OK(res)
}

// Get runs the get action.
func (c *AclController) Get(ctx *app.GetAclContext) error {
	// AclController_Get: start_implement

	policy, err := c.Manager.Get(ctx.PolicyID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	defPolicy, ok := policy.(*ladon.DefaultPolicy)
	if !ok {
		return ctx.InternalServerError(fmt.Errorf("unknown policy type"))
	}
	// AclController_Get: end_implement
	return ctx.OK(toACLPolicyMedia(defPolicy))
}

// ManageAccess runs the manage-access action.
func (c *AclController) ManageAccess(ctx *app.ManageAccessAclContext) error {
	// AclController_ManageAccess: start_implement

	aaPolicy := ctx.Payload

	if aaPolicy.Users == nil {
		aaPolicy.Users = []string{"<.+>"} // Apply to all users
	}

	if aaPolicy.Organizations == nil {
		aaPolicy.Organizations = []string{}
	}

	if aaPolicy.Scopes == nil {
		aaPolicy.Scopes = []string{}
	}

	description := ""
	if aaPolicy.Description != nil {
		description = *aaPolicy.Description
	}

	if len(aaPolicy.Resources) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one resource is required"))
	}

	effect := "Deny"
	if aaPolicy.Allow {
		effect = "Allow"
	}

	aclPolicy := &ladon.DefaultPolicy{
		ID:          uuid.NewV4().String(),
		Description: description,
		Effect:      effect,
		Subjects:    aaPolicy.Users,
		Actions:     aaPolicy.Scopes,
		Resources:   aaPolicy.Resources,
		Conditions:  ladon.Conditions{},
	}

	if len(aaPolicy.Organizations) > 0 {
		orgsCond, err := acl.NewCondition("OrganizationsCondition", aaPolicy.Organizations)
		if err != nil {
			return ctx.InternalServerError(err)
		}
		aclPolicy.Conditions["organizations"] = orgsCond
	}

	if len(aaPolicy.Roles) > 0 {
		rolesCond, err := acl.NewCondition("RolesCondition", aaPolicy.Roles)
		if err != nil {
			return ctx.InternalServerError(err)
		}
		aclPolicy.Conditions["roles"] = rolesCond
	}

	err := c.Manager.Create(aclPolicy)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	// AclController_ManageAccess: end_implement

	return ctx.OK(toACLPolicyMedia(aclPolicy))
}

// UpdatePolicy runs the updatePolicy action.
func (c *AclController) UpdatePolicy(ctx *app.UpdatePolicyAclContext) error {
	// AclController_UpdatePolicy: start_implement

	description := ""
	if ctx.Payload.Description != nil {
		description = *ctx.Payload.Description
	}
	var id string
	if ctx.Payload.ID == nil {
		return ctx.BadRequest(fmt.Errorf("policy id required"))
	}

	if ctx.Payload.Actions == nil || len(ctx.Payload.Actions) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one action is required"))
	}

	if ctx.Payload.Resources == nil || len(ctx.Payload.Resources) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one resource is required"))
	}

	if ctx.Payload.Subjects == nil || len(ctx.Payload.Subjects) == 0 {
		return ctx.BadRequest(fmt.Errorf("at least one subject is required"))
	}

	existing, err := c.Manager.Get(id)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if existing == nil {
		return ctx.NotFound(fmt.Errorf("not found"))
	}

	aclPolicy := &ladon.DefaultPolicy{
		Actions:     ctx.Payload.Actions,
		Description: description,
		Effect:      ctx.Payload.Effect,
		ID:          id,
		Resources:   ctx.Payload.Resources,
		Subjects:    ctx.Payload.Subjects,
		Conditions:  ladon.Conditions{},
	}

	if ctx.Payload.Conditions != nil {
		for _, condDef := range ctx.Payload.Conditions {
			if condDef.Patterns == nil || len(condDef.Patterns) == 0 {
				return ctx.BadRequest(fmt.Errorf("must specify at least one pattern for the condition"))
			}
			cond, err := acl.NewCondition(condDef.Type, condDef.Patterns)
			if err != nil {
				return ctx.BadRequest(err)
			}
			aclPolicy.Conditions[condDef.Name] = cond
		}
	}

	// Replace the policy completely with new data
	err = c.Manager.Update(aclPolicy)
	if err != nil {
		return ctx.InternalServerError(err)
	}

	// AclController_UpdatePolicy: end_implement
	return ctx.OK(toACLPolicyMedia(aclPolicy))
}
