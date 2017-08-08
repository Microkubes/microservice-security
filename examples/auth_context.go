package examples

import (
	"context"
	"fmt"

	"github.com/JormungandrK/microservice-security/auth"
)

// SetAuthInContext sets an auth.Auth object in context and checks for it
func SetAuthInContext() error {
	ctx := context.Background()
	authObj := auth.Auth{
		UserID:        "e027a023-281c-424a-963a-27a32a7b0695",
		Username:      "test-user",
		Roles:         []string{"user", "admin"},
		Organizations: []string{"Jormungandr"},
	}

	ctx = auth.SetAuth(ctx, &authObj)

	hasAuth := auth.HasAuth(ctx)

	if hasAuth {
		fmt.Println("Auth has been set in context.")
	} else {
		return fmt.Errorf("Auth has not been set")
	}
	return nil
}

// RetrieveAuthFromContext first stores an Auth object in context, then retrieves it
// via auth.GetAuth
func RetrieveAuthFromContext() error {
	ctx := context.Background()
	authObj := auth.Auth{
		UserID:        "e027a023-281c-424a-963a-27a32a7b0695",
		Username:      "test-user",
		Roles:         []string{"user", "admin"},
		Organizations: []string{"Jormungandr"},
	}

	ctx = auth.SetAuth(ctx, &authObj)

	retrieved := auth.GetAuth(ctx)

	if retrieved == nil {
		return fmt.Errorf("No auth in context")
	}
	fmt.Println("Auth retrieved from context.")
	return nil
}
