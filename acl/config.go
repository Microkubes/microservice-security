package acl

// DBConfig holds the database configuration parameters.
type DBConfig struct {

	// Host is the database host+port URL
	Host string `json:"host,omitempty"`

	// Username is the username used to access the database
	Username string `json:"user,omitempty"`

	// Password is the databse user password
	Password string `json:"pass,omitempty"`

	// DatabaseName is the name of the database where the server will store the collections
	DatabaseName string `json:"database,omitempty"`
}
