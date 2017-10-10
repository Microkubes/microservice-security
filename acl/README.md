ACL Middleware
==============

This middleware provides access control lists based authorization for the microservices.

Current implementation is based on [Ladon](https://github.com/ory/ladon).

# Configure the ACL Middleware

The middleware requires ```ladon.Manager``` instance so it can load the needed policies.

Once you have a ```ladon.Manager``` configured, you can create and add the ACL middleware to the security chain:

```Go

aclMiddleware := acl.NewACLMiddleware(ladonManager)

securityChain.AddMiddleware(aclMiddleware)

```

# Ladon Manager implementation

This package provides a MongoDB based implementation for ```ladon.Manager```.

You can create new manager using ```NewMongoDBLadonManager```. This requires connection parameters for MongoDB passed in ```config.DBConfig```:

```Go
mongoConf := &config.DBConfig{
  DatabaseName: "my-database",
  Host: "localhost:27017",
  Username: "user",
  Password: "p@ss",
}

manager, err := acl.NewMongoDBLadonManager(&mongoConf)
if err != nil {
  panic(err)
}
```

The database configuration can be read from file.

A special collection with name "ACL" will be created by the manager itself during the starup. The data for ACL policies will be kept in that collection.


# ACL Management API

Because the ACL data is kept usually in a separate store for each microservice, the library contains
a Controller that exposes REST api for managing the ACL policies.

To use the controller you need to set up the data store and create new ACLController. In the
microservice setup add:

```Go

import (
  // other imports

  "github.com/JormungandrK/microservice-security/acl"
  "github.com/JormungandrK/microservice-security/acl/rest"
  restApp "github.com/JormungandrK/microservice-security/acl/rest/app"
)

func main(){
  // standard init here
  manager, cleanup, err := acl.NewMongoDBLadonManager(&acl.DBConfig{
    Host: "localhost:27017",
    DatabaseName: "user-profile",
    Username: "dbuser",
    Password: "dbpass",
  })
  if err != nil {
    panic(err)
  }
  defer cleanup()

  aclController, err := rest.NewAclController(service, manager)
  if err != nil {
    panic(err)
  }
  restApp.MountAclController(service, aclController)
}
```

# ACL Management APIs

## Create Policy

Creates new ACL policy.

* Path: <microservice-url>/acl
* Method: **POST**
* Consumes: ACLPolicy Object (JSON)
* Returns: ACLPolicy Object (JSON)

See bellow for the structure of the ACL Policy object.

## Get Policy

Retrieves an ACL policy by the policy ID.

* Path: <microservice-url>/acl/:policyId
* Method: **GET**
* Returns: ACLPolicy Object (JSON)

## Update ACL Policy

Updates an existing ACL Policy.

* Path: <microservice-url>/acl/:policyId
* Method: **PUT**
* Consumes: ACLPolicy Object (JSON)
* Returns: ACLPolicy Object (JSON)

## Delete an ACL policy

Removes an ACL policy.

* Path: <microservice-url>/acl/:policyId
* Method: **DELETE**
* Consumes: ACLPolicy Object (JSON)
* Returns: ACLPolicy Object (JSON)

## Manage Access

This is a helper service that consumes a more semantic request object and creates
an ACL policy based on it.

* Path: <microservice-url>/acl/access
* Method: **POST**
* Consumes: AccessPolicy Object (JSON)
* Returns: ACLPolicy Object (JSON)

The AccessPolicy Object has the following structure:

```json
{
  "description": "A description of the ACL policy",
  "resources": ["/path/to/specific/resource","/api/user/<.+>"],
  "users": ["user1","test-user-<.+>"],
  "organizations": ["org1","<.+>.jormungandr"],
  "allow": true,
  "scopes": ["api:read", "api:write"],
  "roles": ["user", "system"]
}
```

Where:

* **description** is a description of the policy
* **resources** is a list of resources patterns. You may user regex by placing it in angle brackets - "not-a-regex<this-is-a-regex>".
* **users** is a list of user patterns. You may user regex by placing it in angle brackets - "not-a-regex<this-is-a-regex>".
If no users are specified, the system will add a pattern to match all users - "<.+>".
*  **organizations** is a list of organizations. You may user regex by placing it in angle brackets - "not-a-regex<this-is-a-regex>".
The list of organizations is _optional_.
* **allow** - _true_ or _false_. Whether to allow or deny the requests matching this policy.
* **scopes** - list of scopes patterns. Usually the values are "api:read" or "api:write".
* **roles**  list of roles. You may user regex by placing it in angle brackets - "not-a-regex<this-is-a-regex>".



## ACL Policies types
The ACL Policy Object has the following structure (example):

```json
{
  "id": "4f8b7c93-2368-4019-8d6f-747a9e82ebee",
  "description": "Policy description. Text.",
  "subjects": ["user1","test-user-<.+>"],
  "effect": "allow",
  "resources": ["/path/to/specific/resource","/api/user/<.+>"],
  "actions":["api:read", "api:write"],
  "conditions": [{
      "name": "organizations",
      "type": "OrganizationsCondition",
      "patterns": ["<.+>.jormungandr","some-specific-org"]
    },{
      "name": "roles",
      "type": "RolesCondition",
      "patterns": ["user","admin", "system"]
    },{
      "name": "scopes",
      "type": "ScopesCondition",
      "patterns": ["api:read","api:write"]
    },{
      "name": "createdBy",
      "type": "OwnerCondition"
    }]
}
```
