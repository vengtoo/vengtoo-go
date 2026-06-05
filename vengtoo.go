package vengtoo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultBaseURL = "https://api.vengtoo.com"

// Client is the Vengtoo SDK client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int

	oauth *oauthConfig
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL (e.g., "http://localhost:8181" for local agent).
func WithBaseURL(url string) ClientOption {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithRetries sets the max number of retries on transient (5xx) errors. Default is 2.
func WithRetries(n int) ClientOption {
	return func(c *Client) { c.maxRetries = n }
}

// WithOAuth configures OAuth2 Client Credentials authentication. The SDK will
// exchange these credentials for a short-lived bearer token at
// https://api.vengtoo.com/v1/oauth/token (or the URL set via
// WithOAuthTokenURL), cache it in memory, and refresh it ~60s before expiry.
// Mutually exclusive with providing an API key to NewClient.
func WithOAuth(clientID, clientSecret string) ClientOption {
	return func(c *Client) {
		c.oauth = &oauthConfig{
			clientID:     clientID,
			clientSecret: clientSecret,
			tokenURL:     defaultTokenURL,
		}
	}
}

// WithOAuthTokenURL overrides the OAuth2 token endpoint URL (useful for tests
// and self-hosted Vengtoo installations). Has no effect unless WithOAuth is
// also supplied.
func WithOAuthTokenURL(tokenURL string) ClientOption {
	return func(c *Client) {
		if c.oauth != nil {
			c.oauth.tokenURL = tokenURL
		}
	}
}

// NewClient creates a new Vengtoo client.
// For cloud with API key: vengtoo.NewClient("azx_...")
// For cloud with OAuth:   vengtoo.NewClient("", vengtoo.WithOAuth("client-id", "azx_cs_..."))
// For local agent:        vengtoo.NewClient("", vengtoo.WithBaseURL("http://localhost:8181"))
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		maxRetries: 2,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewClientWithOptions builds a client using only options (no positional API
// key). It returns an error if the combination of auth options is invalid
// (e.g. both apiKey and OAuth provided, or neither for a non-local base URL).
//
// Existing callers should continue using NewClient; this constructor is for
// callers who want construction-time validation of their auth config.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	c := NewClient("", opts...)
	if err := c.validateAuth(); err != nil {
		return nil, err
	}
	return c, nil
}

// validateAuth enforces mutual exclusion between API key and OAuth creds.
// An empty apiKey + no OAuth is allowed to preserve the existing "local
// agent" usage pattern (NewClient("", WithBaseURL(...))).
func (c *Client) validateAuth() error {
	if c.apiKey != "" && c.oauth != nil {
		return errors.New("vengtoo: configure either an API key or OAuth client credentials, not both")
	}
	return nil
}

// Check is a convenience method that returns just the boolean result.
// It accepts action as a plain string for ergonomics and wraps it into an Action object internally.
func (c *Client) Check(ctx context.Context, subject Subject, action string, resource Resource) (bool, error) {
	resp, err := c.Authorize(ctx, &AuthorizeRequest{
		Subject:  subject,
		Resource: resource,
		Action:   Action{Name: action},
	})
	if err != nil {
		return false, err
	}
	return resp.Decision, nil
}

func (c *Client) url() string {
	return c.baseURL + "/access/v1/evaluation"
}

func (c *Client) batchURL() string {
	return c.baseURL + "/access/v1/evaluations"
}

// authHeader resolves the value for the Authorization header on API calls.
// Returns "" if no auth is configured (local-agent mode).
func (c *Client) authHeader(ctx context.Context) (string, error) {
	if c.oauth != nil {
		tok, err := c.oauth.getToken(ctx, c.httpClient)
		if err != nil {
			return "", err
		}
		return "Bearer " + tok, nil
	}
	if c.apiKey != "" {
		return "Bearer " + c.apiKey, nil
	}
	return "", nil
}

// Authorize sends a full authorization request and returns the detailed response.
func (c *Client) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	if err := c.validateAuth(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vengtoo: failed to marshal request: %w", err)
	}

	// OAuth flow gets exactly one 401-triggered refresh+retry across the
	// whole call, independent of maxRetries.
	oauthRetried := false

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.url(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("vengtoo: failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		authVal, err := c.authHeader(ctx)
		if err != nil {
			return nil, err
		}
		if authVal != "" {
			httpReq.Header.Set("Authorization", authVal)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("vengtoo: request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("vengtoo: failed to read response: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var result AuthorizeResponse
			if err := json.Unmarshal(respBody, &result); err != nil {
				return nil, fmt.Errorf("vengtoo: failed to parse response: %w", err)
			}
			return &result, nil
		}

		// On 401 with OAuth, invalidate the cached token and retry once.
		if resp.StatusCode == http.StatusUnauthorized && c.oauth != nil && !oauthRetried {
			c.oauth.invalidate()
			oauthRetried = true
			// Do not count this against maxRetries.
			attempt--
			continue
		}

		apiErr := &Error{StatusCode: resp.StatusCode, Message: string(respBody)}

		// Only retry on 5xx or 429
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			lastErr = apiErr
			continue
		}

		return nil, apiErr
	}

	return nil, lastErr
}

// AuthorizeBatch sends a batch evaluation request (AuthZEN 1.0) and returns
// detailed responses for each evaluation item.
func (c *Client) AuthorizeBatch(ctx context.Context, req *BatchEvaluationRequest) (*BatchEvaluationResponse, error) {
	if err := c.validateAuth(); err != nil {
		return nil, err
	}
	if len(req.Evaluations) == 0 {
		return nil, fmt.Errorf("vengtoo: batch request requires at least one evaluation")
	}
	if len(req.Evaluations) > 50 {
		return nil, fmt.Errorf("vengtoo: batch request exceeds maximum of 50 evaluations")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vengtoo: failed to marshal request: %w", err)
	}

	oauthRetried := false
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.batchURL(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("vengtoo: failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		authVal, err := c.authHeader(ctx)
		if err != nil {
			return nil, err
		}
		if authVal != "" {
			httpReq.Header.Set("Authorization", authVal)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("vengtoo: request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("vengtoo: failed to read response: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var result BatchEvaluationResponse
			if err := json.Unmarshal(respBody, &result); err != nil {
				return nil, fmt.Errorf("vengtoo: failed to parse response: %w", err)
			}
			return &result, nil
		}

		if resp.StatusCode == http.StatusUnauthorized && c.oauth != nil && !oauthRetried {
			c.oauth.invalidate()
			oauthRetried = true
			attempt--
			continue
		}

		apiErr := &Error{StatusCode: resp.StatusCode, Message: string(respBody)}
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			lastErr = apiErr
			continue
		}
		return nil, apiErr
	}

	return nil, lastErr
}

// CheckBatch is a convenience method that returns just the boolean decisions.
func (c *Client) CheckBatch(ctx context.Context, req *BatchEvaluationRequest) ([]bool, error) {
	resp, err := c.AuthorizeBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	results := make([]bool, len(resp.Evaluations))
	for i, eval := range resp.Evaluations {
		results[i] = eval.Decision
	}
	return results, nil
}
