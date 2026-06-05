package vengtoo

import "fmt"

// Error represents an AuthzX API error with status code and message.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("vengtoo: API error (status %d): %s", e.StatusCode, e.Message)
}

// OAuthError represents a failure during the OAuth2 Client Credentials token
// exchange. It is distinct from Error (which wraps API-call failures) so
// customers can tell "bad client_id/client_secret" apart from "bad
// authorization request".
type OAuthError struct {
	StatusCode  int
	Code        string // RFC 6749 error code, e.g. "invalid_client"
	Description string
}

func (e *OAuthError) Error() string {
	if e.Code == "invalid_client" {
		return "vengtoo: OAuth authentication failed: check client_id/client_secret"
	}
	if e.Description != "" {
		return fmt.Sprintf("vengtoo: OAuth token exchange failed (%s): %s", e.Code, e.Description)
	}
	return fmt.Sprintf("vengtoo: OAuth token exchange failed (%s)", e.Code)
}

// IsOAuthError returns true if err is an *OAuthError.
func IsOAuthError(err error) bool {
	_, ok := err.(*OAuthError)
	return ok
}

// IsAuthError returns true if the error is a 401 Unauthorized.
func IsAuthError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.StatusCode == 401
	}
	return false
}

// IsForbidden returns true if the error is a 403 Forbidden.
func IsForbidden(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.StatusCode == 403
	}
	return false
}

// IsNotFound returns true if the error is a 404 Not Found.
func IsNotFound(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.StatusCode == 404
	}
	return false
}

// IsServerError returns true if the error is a 5xx server error.
func IsServerError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.StatusCode >= 500
	}
	return false
}
