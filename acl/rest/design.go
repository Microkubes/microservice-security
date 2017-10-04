package rest

import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
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
	})
})

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

var ACLPolicyPayload = Type("ACLPolicyPayload", func() {
	Description("ACL Policy Payload")
	Attribute("id", String, "Policy ID")
	Attribute("description", String, "Description")
	Attribute("subjects", ArrayOf(String), "Subjects to match the request against.")
	Attribute("effect", String, "allow or deny")
	Attribute("resources", ArrayOf(String), "Resources to which this policy applies.")
	Attribute("actions", ArrayOf(String), "Actions to match the request against.")
	Attribute("conditions", ArrayOf(ConditionType), "Custom conditions")
})

var ConditionType = Type("Condition", func() {
	Description("Custom ACL policy condition")
	Attribute("name", String, "Condition name")
	Attribute("type", String, "Condition type.")
	Attribute("patterns", ArrayOf(String), "Patterns to match the value against.")
})
