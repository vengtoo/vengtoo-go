package vengtoo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func mockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestCheck_Allowed(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/access/v1/evaluation" {
			t.Errorf("expected /access/v1/evaluation, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}

		var req AuthorizeRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Subject.ID != "user-1" {
			t.Errorf("expected subject ID user-1, got %s", req.Subject.ID)
		}
		if req.Action.Name != "read" {
			t.Errorf("expected action name read, got %s", req.Action.Name)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Decision: true,
			Context: &AuthorizeContext{
				Reason:   "role_match",
				PolicyID: "pol-1",
				AccessPath: "role",
			},
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	allowed, err := client.Check(context.Background(),
		Subject{ID: "user-1"},
		"read",
		Resource{ID: "doc-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestCheck_Denied(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Decision: false,
			Context:  &AuthorizeContext{Reason: "no matching policy"},
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	allowed, err := client.Check(context.Background(),
		Subject{ID: "user-1"}, "delete", Resource{ID: "doc-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestAuthorize_FullResponse(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Decision: true,
			Context: &AuthorizeContext{
				Reason:     "direct_access",
				PolicyID:   "pol-123",
				AccessPath: "direct",
			},
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	resp, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1", Type: "user"},
		Resource: Resource{ID: "doc-1", Type: "document"},
		Action:   Action{Name: "read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Error("expected decision=true")
	}
	if resp.Context == nil {
		t.Fatal("expected non-nil context")
	}
	if resp.Context.PolicyID != "pol-123" {
		t.Errorf("expected pol-123, got %s", resp.Context.PolicyID)
	}
	if resp.Context.AccessPath != "direct" {
		t.Errorf("expected direct, got %s", resp.Context.AccessPath)
	}
}

func TestAuthorize_AuthError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("invalid api key"))
	})
	defer srv.Close()

	client := NewClient("bad-key", WithBaseURL(srv.URL))
	_, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   Action{Name: "read"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthError(err) {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestAuthorize_ServerError_Retries(t *testing.T) {
	attempts := 0
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(500)
			w.Write([]byte("internal error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Decision: true,
			Context:  &AuthorizeContext{Reason: "ok"},
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL), WithRetries(2))
	resp, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   Action{Name: "read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Error("expected decision=true after retry")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestAuthorize_NoRetryOn4xx(t *testing.T) {
	attempts := 0
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(400)
		w.Write([]byte("bad request"))
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	_, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   Action{Name: "read"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", attempts)
	}
}

func TestSubject_TypeOptional(t *testing.T) {
	s := Subject{ID: "user-1"}
	data, _ := json.Marshal(s)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["type"]; ok {
		t.Error("type should be omitted when empty")
	}
}

// --- OAuth2 Client Credentials tests ---

// oauthTestServers wires up a token endpoint and an API endpoint on separate
// httptest.Servers so the two behaviors can be asserted independently.
type oauthTestServers struct {
	token   *httptest.Server
	api     *httptest.Server
	exchanges int32
	apiCalls  int32
}

func (s *oauthTestServers) Close() {
	s.token.Close()
	s.api.Close()
}

func newOAuthTestServers(t *testing.T, tokenHandler http.HandlerFunc, apiHandler http.HandlerFunc) *oauthTestServers {
	t.Helper()
	s := &oauthTestServers{}
	s.token = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.exchanges, 1)
		tokenHandler(w, r)
	}))
	s.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.apiCalls, 1)
		apiHandler(w, r)
	}))
	return s
}

func TestOAuth_TokenExchangeHappyPath(t *testing.T) {
	srv := newOAuthTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Errorf("expected form content-type, got %s", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("expected grant_type=client_credentials, got %s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "azx_cs_secret" {
				t.Errorf("unexpected creds in body: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "jwt.token.here",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer jwt.token.here" {
				t.Errorf("expected Bearer jwt.token.here, got %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: true,
				Context:  &AuthorizeContext{Reason: "ok"},
			})
		},
	)
	defer srv.Close()

	client := NewClient("",
		WithBaseURL(srv.api.URL),
		WithOAuth("cid", "azx_cs_secret"),
		WithOAuthTokenURL(srv.token.URL),
	)
	allowed, err := client.Check(context.Background(), Subject{ID: "u-1"}, "read", Resource{ID: "d-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allowed")
	}
	if got := atomic.LoadInt32(&srv.exchanges); got != 1 {
		t.Errorf("expected 1 token exchange, got %d", got)
	}
}

func TestOAuth_InvalidClientClearError(t *testing.T) {
	srv := newOAuthTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_client"}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("API should not be called when token exchange fails")
		},
	)
	defer srv.Close()

	client := NewClient("",
		WithBaseURL(srv.api.URL),
		WithOAuth("cid", "azx_cs_wrong"),
		WithOAuthTokenURL(srv.token.URL),
	)
	_, err := client.Check(context.Background(), Subject{ID: "u-1"}, "read", Resource{ID: "d-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsOAuthError(err) {
		t.Errorf("expected OAuthError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "check client_id/client_secret") {
		t.Errorf("expected setup-hint message, got %q", err.Error())
	}
}

func TestOAuth_CachedTokenReusedAcrossCalls(t *testing.T) {
	srv := newOAuthTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok-abc",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: true,
				Context:  &AuthorizeContext{Reason: "ok"},
			})
		},
	)
	defer srv.Close()

	client := NewClient("",
		WithBaseURL(srv.api.URL),
		WithOAuth("cid", "azx_cs_secret"),
		WithOAuthTokenURL(srv.token.URL),
	)

	for i := 0; i < 3; i++ {
		if _, err := client.Check(context.Background(), Subject{ID: "u-1"}, "read", Resource{ID: "d-1"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&srv.exchanges); got != 1 {
		t.Errorf("expected 1 token exchange across 3 calls, got %d", got)
	}
	if got := atomic.LoadInt32(&srv.apiCalls); got != 3 {
		t.Errorf("expected 3 API calls, got %d", got)
	}
}

func TestOAuth_401TriggersRefreshAndRetry(t *testing.T) {
	var tokenCounter int32
	srv := newOAuthTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&tokenCounter, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok-" + string(rune('0'+n)),
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			// First token rejected; second accepted.
			if auth == "Bearer tok-1" {
				w.WriteHeader(401)
				w.Write([]byte("stale token"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(AuthorizeResponse{
				Decision: true,
				Context:  &AuthorizeContext{Reason: "ok"},
			})
		},
	)
	defer srv.Close()

	client := NewClient("",
		WithBaseURL(srv.api.URL),
		WithOAuth("cid", "azx_cs_secret"),
		WithOAuthTokenURL(srv.token.URL),
	)
	allowed, err := client.Check(context.Background(), Subject{ID: "u-1"}, "read", Resource{ID: "d-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allowed after refresh+retry")
	}
	if got := atomic.LoadInt32(&srv.exchanges); got != 2 {
		t.Errorf("expected 2 token exchanges (initial + refresh), got %d", got)
	}
	if got := atomic.LoadInt32(&srv.apiCalls); got != 2 {
		t.Errorf("expected 2 API calls (401 + retry), got %d", got)
	}
}

func TestOAuth_401RetryOnlyOnce(t *testing.T) {
	srv := newOAuthTestServers(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "tok",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			w.Write([]byte("nope"))
		},
	)
	defer srv.Close()

	client := NewClient("",
		WithBaseURL(srv.api.URL),
		WithOAuth("cid", "azx_cs_secret"),
		WithOAuthTokenURL(srv.token.URL),
	)
	_, err := client.Check(context.Background(), Subject{ID: "u-1"}, "read", Resource{ID: "d-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthError(err) {
		t.Errorf("expected auth error after retry exhausted, got %v", err)
	}
	// Exactly two API calls: initial + one refresh-retry. No infinite loop.
	if got := atomic.LoadInt32(&srv.apiCalls); got != 2 {
		t.Errorf("expected 2 API calls, got %d", got)
	}
}

func TestOAuth_ConstructionError_BothAuthModes(t *testing.T) {
	// apiKey + OAuth is invalid. NewClient is lenient (keeps the existing
	// public signature stable), so the error surfaces on the first call.
	c := NewClient("azx_key", WithOAuth("cid", "azx_cs_secret"))
	_, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Subject: Subject{ID: "u-1"}, Resource: Resource{ID: "d-1"}, Action: Action{Name: "read"},
	})
	if err == nil {
		t.Fatal("expected validation error when both apiKey and OAuth set")
	}
	if !strings.Contains(err.Error(), "either an API key or OAuth") {
		t.Errorf("unexpected message: %q", err.Error())
	}

	// OAuth-only should construct cleanly via NewClientWithOptions.
	if _, err := NewClientWithOptions(WithOAuth("cid", "azx_cs_secret")); err != nil {
		t.Errorf("OAuth-only should construct cleanly: %v", err)
	}
}
