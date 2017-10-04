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
