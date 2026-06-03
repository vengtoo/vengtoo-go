package main

import (
	"context"
	"fmt"
	"log"

	authzx "github.com/vengtoo/vengtoo-go"
)

func main() {
	client := authzx.NewClient("azx_your_api_key_here")

	ctx := context.Background()

	allowed, err := client.Check(ctx,
		authzx.Subject{ID: "user-123"},
		"read",
		authzx.Resource{ID: "doc-456"},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Allowed:", allowed)

	resp, err := client.Authorize(ctx, &authzx.AuthorizeRequest{
		Subject:  authzx.Subject{ID: "user-123"},
		Resource: authzx.Resource{ID: "doc-456"},
		Action:   authzx.Action{Name: "read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	reason := ""
	accessPath := ""
	if resp.Context != nil {
		reason = resp.Context.Reason
		accessPath = resp.Context.AccessPath
	}
	fmt.Printf("Decision=%v Reason=%q Path=%s\n", resp.Decision, reason, accessPath)
}
