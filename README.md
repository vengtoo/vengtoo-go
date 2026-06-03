# Vengtoo Go SDK

Go client for [Vengtoo](https://vengtoo.com) — works with both Vengtoo Cloud and the Vengtoo Agent.

Current release: **v1.0.1**

## Install

```bash
go get github.com/vengtoo/vengtoo-go@v1.0.1
```

## Usage

### Cloud Mode

```go
package main

import (
    "context"
    "fmt"
    vengtoo "github.com/vengtoo/vengtoo-go"
)

func main() {
    client := vengtoo.NewClient("azx_...")

    allowed, err := client.Check(context.Background(),
        vengtoo.Subject{ID: "user:123", Type: "user", Roles: []string{"editor"}},
        "read",
        vengtoo.Resource{Type: "document", ID: "doc:456"},
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
client := vengtoo.NewClient("",
    vengtoo.WithOAuth("my-client-id", "azx_cs_..."),
)
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.vengtoo.com/identity-srv/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both an API key and `WithOAuth(...)` is rejected. A bad `client_id` / `client_secret` surfaces as a distinct `*vengtoo.OAuthError` (check with `vengtoo.IsOAuthError(err)`) with a message telling you to recheck your credentials.

### Agent Mode (local)

```go
client := vengtoo.NewClient("", vengtoo.WithBaseURL("http://localhost:8181"))
```

### Full Authorize Response

```go
resp, err := client.Authorize(ctx, &vengtoo.AuthorizeRequest{
    Subject:  vengtoo.Subject{ID: "user:123", Type: "user"},
    Resource: vengtoo.Resource{Type: "document", ID: "doc:456"},
    Action:   vengtoo.Action{Name: "read"},
    Context:  map[string]interface{}{"ip": "10.0.0.1"},
})
// resp.Decision (bool), resp.Context.Reason, resp.Context.PolicyID, resp.Context.AccessPath
```

### net/http Middleware

```go
mux := http.NewServeMux()
mux.Handle("/documents/", client.HTTPMiddleware("document", "read", "X-User-ID")(handler))
```

### Gin Middleware

```go
func AuthzMiddleware(client *vengtoo.Client, resourceType, action string) gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed, err := client.Check(c.Request.Context(),
            vengtoo.Subject{ID: c.GetHeader("X-User-ID"), Type: "user"},
            action,
            vengtoo.Resource{Type: resourceType, ID: c.Param("id")},
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
vengtoo.NewClient(apiKey,
    vengtoo.WithBaseURL("http://localhost:8181"),  // Custom URL
    vengtoo.WithHTTPClient(customHTTPClient),       // Custom http.Client
    vengtoo.WithTimeout(5 * time.Second),           // Custom timeout
    vengtoo.WithRetries(3),                         // Max retries on 5xx/429 (default: 2)
)
```

## Error Handling

```go
resp, err := client.Authorize(ctx, req)
if err != nil {
    if vengtoo.IsAuthError(err) {
        // 401 — bad API key or expired token
    }
    if vengtoo.IsForbidden(err) {
        // 403
    }
    if vengtoo.IsOAuthError(err) {
        // bad client_id / client_secret
    }
    if vengtoo.IsServerError(err) {
        // 5xx — retries exhausted
    }
}
```

The SDK automatically retries on 5xx and 429 responses (default: 2 retries with linear backoff). 4xx errors are never retried. With OAuth, a 401 triggers one token refresh before failing.

## Types

| Type                | Fields                                            |
| ------------------- | ------------------------------------------------- |
| `Subject`           | `ID`, `Type`, `Attributes`, `Properties`, `Roles` |
| `Resource`          | `Type`, `ID`, `Attributes`, `Properties`          |
| `AuthorizeRequest`  | `Subject`, `Resource`, `Action`, `Context`        |
| `AuthorizeResponse` | `Decision`, `Context *AuthorizeContext`           |
| `AuthorizeContext`  | `Reason`, `ReasonCode`, `PolicyID`, `AccessPath`  |
| `Error`             | `StatusCode`, `Message`                           |
| `OAuthError`        | `StatusCode`, `Code`, `Description`               |
