package rest

import (
	"fmt"

	"github.com/Microkubes/microservice-security/acl"
	"github.com/Microkubes/microservice-security/acl/rest/app"
	"github.com/keitaroinc/goa"
	"github.com/ory/ladon"
	uuid "github.com/satori/go.uuid"
)

// ACLController implements the acl resource.
type ACLController struct {
	*goa.Controller
	ladon.Manager
}

// NewACLController creates a acl controller.
func NewACLController(service *goa.Service, manager ladon.Manager) (*ACLController, error) {
	if err := addDefaultACLControllerPolicies(manager); err != nil {
		return nil, err
	}
	return &ACLController{
		Controller: service.NewController("AclController"),
		Manager:    manager,
	}, nil
}

func addDefaultACLControllerPolicies(manager ladon.Manager) error {
	// allow admin user to manage ACL policies
	if err := addOrUpdatePolicy(&ladon.DefaultPolicy{
		ID:          "admin-access-allow-all",
		Description: "Allow Admin users to manage all ACL policies",
		Actions:     []string{"api:read", "api:write"},
		Effect:      ladon.AllowAccess,
		Resources:   []string{"/acl/<.+>"},
		Subjects:    []string{"<.+>"}, // all users
	}, manager); err != nil {
		return err
	}

	// allow access to the creator of the ACL policy
	if err := addOrUpdatePolicy(&ladon.DefaultPolicy{
		ID:          "owner-access-allow-all",
		Description: "Allow the creator of the policies to manage its policies",
		Actions:     []string{"api:read", "api:write"},
		Effect:      ladon.AllowAccess,
		Resources:   []string{"/acl/<.+>"},
		Subjects:    []string{"<.+>"}, // all users
		Conditions: ladon.Conditions{
			"createdBy": &acl.OwnerCondition{},
		},
	}, manager); err != nil {
		return err
	}
	return nil
}

func addOrUpdatePolicy(policy ladon.Policy, manager ladon.Manager) error {
	existing, err := manager.Get(policy.GetID())
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	return manager.Create(policy)
}

// CreatePolicy runs the createPolicy action.
func (c *ACLController) CreatePolicy(ctx *app.CreatePolicyAclContext) error {
	// AclController_CreatePolicy: start_implement

	description := ""
	if ctx.Payload.Description != nil {
		description = *ctx.Payload.Description
	}
	var id string
	if ctx.Payload.ID != nil && *ctx.Payload.ID != "" {
		id = *ctx.Payload.ID
	} else {
		randUUID, err := uuid.NewV4()
		if err != nil {
			return err
		}
		id = randUUID.String()
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
func (c *ACLController) DeletePolicy(ctx *app.DeletePolicyAclContext) error {
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
func (c *ACLController) Get(ctx *app.GetAclContext) error {
	// AclController_Get: start_implement

	policy, err := c.Manager.Get(ctx.PolicyID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if policy == nil {
		return ctx.NotFound(fmt.Errorf("not-found"))
	}
	defPolicy, ok := policy.(*ladon.DefaultPolicy)
	if !ok {
		return ctx.InternalServerError(fmt.Errorf("unknown policy type"))
	}
	// AclController_Get: end_implement
	return ctx.OK(toACLPolicyMedia(defPolicy))
}

// ManageAccess runs the manage-access action.
func (c *ACLController) ManageAccess(ctx *app.ManageAccessAclContext) error {
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

	effect := "deny"
	if aaPolicy.Allow {
		effect = "allow"
	}

	randUUID, err := uuid.NewV4()
	if err != nil {
		return err
	}

	aclPolicy := &ladon.DefaultPolicy{
		ID:          randUUID.String(),
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

	err = c.Manager.Create(aclPolicy)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	// AclController_ManageAccess: end_implement

	return ctx.OK(toACLPolicyMedia(aclPolicy))
}

// UpdatePolicy runs the updatePolicy action.
func (c *ACLController) UpdatePolicy(ctx *app.UpdatePolicyAclContext) error {
	// AclController_UpdatePolicy: start_implement

	description := ""
	if ctx.Payload.Description != nil {
		description = *ctx.Payload.Description
	}
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

	existing, err := c.Manager.Get(ctx.PolicyID)
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
		ID:          ctx.PolicyID,
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
