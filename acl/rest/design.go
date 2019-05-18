package rest

import (
	. "github.com/keitaroinc/goa/design"
	. "github.com/keitaroinc/goa/design/apidsl"
)

var _ = API("acl-manager", func() {
	Title("ACL Management API")
	Description("ACL Management REST services")
	Version("1.0")
	Scheme("http")
	Host("localhost:8080")
})

var _ = Resource("acl", func() {
	BasePath("acl")

	DefaultMedia(ACLPolicyMedia)

	Action("get", func() {
		Description("Retrieve a policy by ID")
		Routing(GET("/:policyId"))
		Params(func() {
			Param("policyId", String, "Policy ID")
		})
		Response(OK, ACLPolicyMedia)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("createPolicy", func() {
		Description("Creates new ACL policy")
		Routing(POST(""))
		Payload(ACLPolicyPayload)
		Response(Created, ACLPolicyMedia)
		Response(BadRequest, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("updatePolicy", func() {
		Description("Updates an existing ACL Policy")
		Routing(PUT("/:policyId"))
		Params(func() {
			Param("policyId", String, "The policy ID")
		})
		Payload(ACLPolicyPayload)
		Response(OK, ACLPolicyMedia)
		Response(BadRequest, ErrorMedia)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})
	Action("deletePolicy", func() {
		Description("Deletes an ACL policy")
		Routing(DELETE("/:policyId"))
		Params(func() {
			Param("policyId", String, "The policy ID")
		})
		Response(OK)
		Response(NotFound, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})

	Action("manage-access", func() {
		Description("Allow or deny access to users of certain organization or particular users to particular resources.")
		Routing(POST("/access"))
		Payload(AccessPolicyPayload)
		Response(OK, ACLPolicyMedia)
		Response(BadRequest, ErrorMedia)
		Response(InternalServerError, ErrorMedia)
	})

})

// ACLPolicyMedia defines the media type used to render ACLPolicy.
var ACLPolicyMedia = MediaType("application/jormungandr-acl-policy+json", func() {
	TypeName("ACLPolicy")
	Reference(ACLPolicyPayload)

	Attributes(func() {
		Attribute("id", String, "Policy ID")
		Attribute("description", String, "Policy description")
		Attribute("subjects", ArrayOf(String), "Subjects to match the request against.")
		Attribute("effect", String, "allow or deny")
		Attribute("resources", ArrayOf(String), "Resources to which this policy applies.")
		Attribute("actions", ArrayOf(String), "Actions to match the request against.")
		Attribute("conditions", ArrayOf(ConditionType), "Custom conditions")
		Attribute("owner", String, "Owner of the policy")

	})

	View("default", func() {
		Attribute("id", String, "Policy ID")
		Attribute("description", String, "Policy description")
		Attribute("subjects", ArrayOf(String), "Subjects to match the request against.")
		Attribute("effect", String, "allow or deny")
		Attribute("resources", ArrayOf(String), "Resources to which this policy applies.")
		Attribute("actions", ArrayOf(String), "Actions to match the request against.")
		Attribute("conditions", ArrayOf(ConditionType), "Custom conditions")
	})

})

// ACLPolicyPayload defines the payload for ACLPolicy.
var ACLPolicyPayload = Type("ACLPolicyPayload", func() {
	Description("ACL Policy Payload")
	Attribute("id", String, "Policy ID")
	Attribute("description", String, "Description")
	Attribute("subjects", ArrayOf(String), "Subjects to match the request against.")
	Attribute("effect", String, "allow or deny")
	Attribute("resources", ArrayOf(String), "Resources to which this policy applies.")
	Attribute("actions", ArrayOf(String), "Actions to match the request against.")
	Attribute("conditions", ArrayOf(ConditionType), "Custom conditions")
	Required("resources", "effect", "subjects")
})

// ConditionType defines the condition type.
var ConditionType = Type("Condition", func() {
	Description("Custom ACL policy condition")
	Attribute("name", String, "Condition name")
	Attribute("type", String, "Condition type.")
	Attribute("patterns", ArrayOf(String), "Patterns to match the value against.")
	Required("name", "type", "patterns")
})

// AccessPolicyPayload defines the payload for AccessPolicy.
var AccessPolicyPayload = Type("AccessPolicyPayload", func() {
	Description("Payload to allow or deny access to resources.")
	Attribute("description", String, "Description of the policy")
	Attribute("resources", ArrayOf(String), "Resources patterns")
	Attribute("users", ArrayOf(String), "Users patterns")
	Attribute("organizations", ArrayOf(String), "Organizations patterns")
	Attribute("allow", Boolean, "Whether to allow access")
	Attribute("scopes", ArrayOf(String), "Which scopes are allowed")
	Attribute("roles", ArrayOf(String), "Which roles are allowed")
	Required("resources", "allow")
})
