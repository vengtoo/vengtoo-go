package vengtoo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultTokenURL is the OAuth2 token endpoint for AuthzX Cloud.
const defaultTokenURL = "https://api.vengtoo.com/v1/oauth/token"

// refreshSkew is how long before expiry we proactively refresh a cached token.
const refreshSkew = 60 * time.Second

// tokenResponse mirrors the RFC 6749 §5.1 success body from the token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// tokenErrorResponse mirrors the RFC 6749 §5.2 error body.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// oauthConfig holds OAuth2 Client Credentials configuration.
type oauthConfig struct {
	clientID     string
	clientSecret string
	tokenURL     string

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

// getToken returns a valid access token, fetching or refreshing as needed.
func (o *oauthConfig) getToken(ctx context.Context, hc *http.Client) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cached != "" && time.Now().Before(o.expiresAt.Add(-refreshSkew)) {
		return o.cached, nil
	}
	return o.fetchLocked(ctx, hc)
}

// invalidate clears the cached token so the next call forces a refresh.
func (o *oauthConfig) invalidate() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cached = ""
	o.expiresAt = time.Time{}
}

// fetchLocked performs the token exchange. Caller must hold o.mu.
func (o *oauthConfig) fetchLocked(ctx context.Context, hc *http.Client) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", o.clientID)
	form.Set("client_secret", o.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("vengtoo: failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("vengtoo: OAuth token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("vengtoo: failed to read OAuth token response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return "", fmt.Errorf("vengtoo: failed to parse OAuth token response: %w", err)
		}
		if tr.AccessToken == "" {
			return "", &OAuthError{Code: "invalid_response", Description: "token endpoint returned empty access_token"}
		}
		o.cached = tr.AccessToken
		ttl := time.Duration(tr.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = time.Hour
		}
		o.expiresAt = time.Now().Add(ttl)
		return o.cached, nil
	}

	// Try to decode RFC 6749 error body for a better message.
	var te tokenErrorResponse
	_ = json.Unmarshal(body, &te)
	if resp.StatusCode == http.StatusUnauthorized || te.Error == "invalid_client" {
		return "", &OAuthError{
			StatusCode:  resp.StatusCode,
			Code:        firstNonEmpty(te.Error, "invalid_client"),
			Description: te.ErrorDescription,
		}
	}
	return "", &OAuthError{
		StatusCode:  resp.StatusCode,
		Code:        firstNonEmpty(te.Error, "token_endpoint_error"),
		Description: firstNonEmpty(te.ErrorDescription, string(body)),
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
