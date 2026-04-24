# AuthzX Go SDK

Go client for [AuthzX](https://authzx.com) — works with both AuthzX Cloud and the AuthzX Agent.

Current release: **v0.3.0**

## Install

```bash
go get github.com/authzx/authzx-go@v0.3.0
```

## Usage

### Cloud Mode

```go
package main

import (
    "context"
    "fmt"
    authzx "github.com/authzx/authzx-go"
)

func main() {
    client := authzx.NewClient("azx_...")

    allowed, err := client.Check(context.Background(),
        authzx.Subject{ID: "user:123", Type: "user", Roles: []string{"editor"}},
        "read",
        authzx.Resource{Type: "document", ID: "doc:456"},
    )
    if err != nil {
        panic(err)
    }
    fmt.Println("Allowed:", allowed)
}
```

### OAuth2 Client Credentials

For service-to-service auth, use an OAuth2 client (`client_id` + `client_secret`, where the secret is prefixed `azx_cs_`). The SDK exchanges credentials at the token endpoint, caches the JWT in memory, and refreshes ~60s before expiry.

```go
client := authzx.NewClient("",
    authzx.WithOAuth("my-client-id", "azx_cs_..."),
)
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.authzx.com/identity-srv/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both an API key and `WithOAuth(...)` is rejected. A bad `client_id` / `client_secret` surfaces as a distinct `*authzx.OAuthError` (check with `authzx.IsOAuthError(err)`) with a message telling you to recheck your credentials.

### Agent Mode (local)

```go
client := authzx.NewClient("", authzx.WithBaseURL("http://localhost:8181"))
```

### Full Authorize Response

```go
resp, err := client.Authorize(ctx, &authzx.AuthorizeRequest{
    Subject:  authzx.Subject{ID: "user:123", Type: "user"},
    Resource: authzx.Resource{Type: "document", ID: "doc:456"},
    Action:   "read",
    Context:  map[string]interface{}{"ip": "10.0.0.1"},
})
// resp.Allowed, resp.Reason, resp.PolicyID, resp.AccessPath
```

### net/http Middleware

```go
mux := http.NewServeMux()
mux.Handle("/documents/", client.HTTPMiddleware("document", "read", "X-User-ID")(handler))
```

### Gin Middleware

```go
func AuthzMiddleware(client *authzx.Client, resourceType, action string) gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed, err := client.Check(c.Request.Context(),
            authzx.Subject{ID: c.GetHeader("X-User-ID"), Type: "user"},
            action,
            authzx.Resource{Type: resourceType, ID: c.Param("id")},
        )
        if err != nil || !allowed {
            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
            return
        }
        c.Next()
    }
}

router.GET("/documents/:id", AuthzMiddleware(client, "document", "read"), handler)
```

### Options

```go
authzx.NewClient(apiKey,
    authzx.WithBaseURL("http://localhost:8181"),  // Custom URL
    authzx.WithHTTPClient(customHTTPClient),       // Custom http.Client
    authzx.WithTimeout(5 * time.Second),           // Custom timeout
    authzx.WithRetries(3),                         // Max retries on 5xx/429 (default: 2)
)
```

## Error Handling

```go
resp, err := client.Authorize(ctx, req)
if err != nil {
    if authzx.IsAuthError(err) {
        // 401 — bad API key or expired token
    }
    if authzx.IsForbidden(err) {
        // 403
    }
    if authzx.IsOAuthError(err) {
        // bad client_id / client_secret
    }
    if authzx.IsServerError(err) {
        // 5xx — retries exhausted
    }
}
```

The SDK automatically retries on 5xx and 429 responses (default: 2 retries with linear backoff). 4xx errors are never retried. With OAuth, a 401 triggers one token refresh before failing.

## Types

| Type | Fields |
|------|--------|
| `Subject` | `ID`, `Type`, `Attributes`, `Roles` |
| `Resource` | `Type`, `ID`, `Attributes` |
| `AuthorizeRequest` | `Subject`, `Resource`, `Action`, `Context` |
| `AuthorizeResponse` | `Allowed`, `Reason`, `PolicyID`, `AccessPath` |
| `Error` | `StatusCode`, `Message` |
| `OAuthError` | `StatusCode`, `Code`, `Description` |
