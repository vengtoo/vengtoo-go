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

// WithOAuthTokenURL overrides the OAuth2 token endpoint URL. Intended for
// tests (point at a mock token server). Has no effect unless WithOAuth is
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
func (c *Client) Check(ctx context.Context, subject Subject, action string, resource Resource, reqCtx ...map[string]interface{}) (bool, error) {
	req := &AuthorizeRequest{
		Subject:  subject,
		Resource: resource,
		Action:   Action{Name: action},
	}
	if len(reqCtx) > 0 {
		req.Context = reqCtx[0]
	}
	resp, err := c.Authorize(ctx, req)
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
	if req.Subject.Type == "" {
		return nil, errors.New("vengtoo: subject.type is required")
	}
	if req.Resource.Type == "" {
		return nil, errors.New("vengtoo: resource.type is required")
	}

	// Default resource.id to "*" when neither id nor external_id is provided
	// so the engine evaluates type-level policies rather than skipping them.
	wireReq := req
	if wireReq.Resource.ID == "" && wireReq.Resource.ExternalID == "" {
		r := wireReq.Resource
		r.ID = "*"
		wireReq = &AuthorizeRequest{
			Subject:  req.Subject,
			Resource: r,
			Action:   req.Action,
			Context:  req.Context,
		}
	}
	body, err := json.Marshal(wireReq)
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

	// Normalize type-level resources: when neither id nor external_id is set,
	// send id="*" so the engine evaluates type-level policies (mirrors Authorize).
	wireEvals := make([]BatchEvalItem, len(req.Evaluations))
	for i, item := range req.Evaluations {
		if item.Resource != nil && item.Resource.ID == "" && item.Resource.ExternalID == "" {
			r := *item.Resource
			r.ID = "*"
			item.Resource = &r
		}
		wireEvals[i] = item
	}
	wireReq := &BatchEvaluationRequest{Evaluations: wireEvals}

	body, err := json.Marshal(wireReq)
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

// CreateDelegation grants delegate the ability to act on behalf of delegator.
// The delegation is enforced server-side at every authorization check — the
// delegate's effective permissions are the intersection of its own policies
// and the delegator's policies (scope attenuation, not escalation).
func (c *Client) CreateDelegation(ctx context.Context, req *CreateDelegationRequest) (*Delegation, error) {
	if err := c.validateAuth(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vengtoo: failed to marshal delegation request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/delegations", bytes.NewReader(body))
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
		return nil, fmt.Errorf("vengtoo: delegation request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vengtoo: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, &Error{StatusCode: resp.StatusCode, Message: string(respBody)}
	}

	var delegation Delegation
	if err := json.Unmarshal(respBody, &delegation); err != nil {
		return nil, fmt.Errorf("vengtoo: failed to parse delegation response: %w", err)
	}
	return &delegation, nil
}

// RevokeDelegation revokes an existing delegation by ID. Once revoked, the
// delegate immediately loses the delegator's permission scope.
func (c *Client) RevokeDelegation(ctx context.Context, id string) error {
	if err := c.validateAuth(); err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/v1/delegations/"+id, nil)
	if err != nil {
		return fmt.Errorf("vengtoo: failed to create request: %w", err)
	}

	authVal, err := c.authHeader(ctx)
	if err != nil {
		return err
	}
	if authVal != "" {
		httpReq.Header.Set("Authorization", authVal)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("vengtoo: revoke delegation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &Error{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return nil
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

// PollingOptions configures AuthorizeWithPolling behavior.
type PollingOptions struct {
	// Timeout is how long to wait for human approval. Default: 5 minutes.
	Timeout time.Duration
	// MaxNetworkErrors is the max consecutive network failures before returning
	// a polling_error result. Default: 3.
	MaxNetworkErrors int
	// OnPending is called once when the request first enters authorization_pending
	// state. authReqID and expiresIn may be empty/zero if not returned by server.
	OnPending func(authReqID string, expiresIn int)
}

// AuthorizeWithPolling is like Authorize but handles HITL polling automatically.
//
// If the initial response is authorization_pending, it waits for a human to
// approve in the Vengtoo dashboard, polling at the server-recommended interval.
// Returns an AuthorizeResponse in all cases — never returns an error for
// pending/timeout/network errors, so every outcome is handled uniformly.
//
// Distinct reason_codes in the returned context:
//
//	"approval_timeout" — no human responded within the timeout
//	"polling_error"    — network errors persisted beyond MaxNetworkErrors retries
func (c *Client) AuthorizeWithPolling(ctx context.Context, req *AuthorizeRequest, opts *PollingOptions) (*AuthorizeResponse, error) {
	if opts == nil {
		opts = &PollingOptions{}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	maxNetworkErrors := opts.MaxNetworkErrors
	if maxNetworkErrors == 0 {
		maxNetworkErrors = 3
	}

	result, err := c.Authorize(ctx, req)
	if err != nil {
		return nil, err // propagate initial call errors
	}
	if result.Decision {
		return result, nil
	}

	reasonCode := ""
	if result.Context != nil {
		reasonCode = result.Context.ReasonCode
	}
	if reasonCode != "authorization_pending" {
		return result, nil
	}

	// Fire onPending once on first entering pending state.
	if opts.OnPending != nil {
		var authReqID string
		var expiresIn int
		if result.Context != nil {
			authReqID = result.Context.AuthReqID
			expiresIn = result.Context.ExpiresIn
		}
		opts.OnPending(authReqID, expiresIn)
	}

	deadline := time.Now().Add(timeout)
	networkErrors := 0

	for time.Now().Before(deadline) {
		interval := 6 // default: 5s server + 1s buffer
		if result.Context != nil && result.Context.Interval > 0 {
			interval = result.Context.Interval + 1
		}
		select {
		case <-ctx.Done():
			return &AuthorizeResponse{
				Decision: false,
				Context:  &AuthorizeContext{ReasonCode: "approval_timeout"},
			}, nil
		case <-time.After(time.Duration(interval) * time.Second):
		}

		if time.Now().After(deadline) {
			break
		}

		result, err = c.Authorize(ctx, req)
		if err != nil {
			networkErrors++
			if networkErrors >= maxNetworkErrors {
				return &AuthorizeResponse{
					Decision: false,
					Context:  &AuthorizeContext{ReasonCode: "polling_error"},
				}, nil
			}
			backoff := time.Duration(min(networkErrors*2, 10)) * time.Second
			select {
			case <-ctx.Done():
				return &AuthorizeResponse{Decision: false, Context: &AuthorizeContext{ReasonCode: "approval_timeout"}}, nil
			case <-time.After(backoff):
			}
			continue
		}
		networkErrors = 0

		if result.Decision {
			return result, nil
		}

		pollCode := ""
		if result.Context != nil {
			pollCode = result.Context.ReasonCode
		}
		if pollCode == "slow_down" {
			continue
		}
		if pollCode != "authorization_pending" {
			return result, nil
		}
	}

	return &AuthorizeResponse{
		Decision: false,
		Context:  &AuthorizeContext{ReasonCode: "approval_timeout"},
	}, nil
}

// WithDelegation creates a delegation, calls fn with the delegation ID, then
// always revokes the delegation — even if fn panics or returns an error.
// This ensures the agent never retains access beyond the task boundary.
//
// Example:
//
//	err := client.WithDelegation(ctx, &vengtoo.CreateDelegationRequest{
//	    DelegatorID: johnEntityID,
//	    DelegateID:  workflowEntityID,
//	}, func(delegationID string) error {
//	    return runWorkflow(ctx)
//	})
func (c *Client) WithDelegation(ctx context.Context, req *CreateDelegationRequest, fn func(delegationID string) error) error {
	d, err := c.CreateDelegation(ctx, req)
	if err != nil {
		return fmt.Errorf("vengtoo: failed to create delegation: %w", err)
	}

	var fnErr error
	defer func() {
		if rErr := c.RevokeDelegation(context.Background(), d.ID); rErr != nil && fnErr == nil {
			fnErr = fmt.Errorf("vengtoo: failed to revoke delegation %s: %w", d.ID, rErr)
		}
	}()

	fnErr = fn(d.ID)
	return fnErr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
