package vengtoo

import "time"

// Subject represents the entity performing the action.
type Subject struct {
	ID         string                 `json:"id,omitempty"`
	ExternalID string                 `json:"external_id,omitempty"`
	Type       string                 `json:"type,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Resource represents the target of the action.
type Resource struct {
	ID         string                 `json:"id,omitempty"`
	ExternalID string                 `json:"external_id,omitempty"`
	Type       string                 `json:"type,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Action represents an authorization action (AuthZEN 1.0).
type Action struct {
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// AuthorizeRequest is the input for an authorization check.
type AuthorizeRequest struct {
	Subject  Subject                `json:"subject"`
	Resource Resource               `json:"resource"`
	Action   Action                 `json:"action"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// AuthorizeContext holds detailed context about an authorization decision.
type AuthorizeContext struct {
	Reason     string `json:"reason,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	PolicyID   string `json:"policy_id,omitempty"`
	AccessPath string `json:"access_path,omitempty"`
	// HITL fields — present when reason_code is "authorization_pending".
	AuthReqID  string `json:"auth_req_id,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
	Interval   int    `json:"interval,omitempty"`
}

// AuthorizeResponse is the result of an authorization check.
type AuthorizeResponse struct {
	Decision bool              `json:"decision"`
	Context  *AuthorizeContext `json:"context,omitempty"`
}

// BatchEvalItem is a single evaluation within a batch request.
// Nil fields inherit from the top-level defaults in BatchEvaluationRequest.
type BatchEvalItem struct {
	Subject  *Subject               `json:"subject,omitempty"`
	Action   *Action                `json:"action,omitempty"`
	Resource *Resource              `json:"resource,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// BatchOptions configures batch evaluation behavior.
type BatchOptions struct {
	EvaluationsSemantic string `json:"evaluations_semantic,omitempty"`
}

// BatchEvaluationRequest is the input for a batch authorization check
// (AuthZEN 1.0 POST /access/v1/evaluations).
type BatchEvaluationRequest struct {
	Subject     *Subject               `json:"subject,omitempty"`
	Action      *Action                `json:"action,omitempty"`
	Resource    *Resource              `json:"resource,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Evaluations []BatchEvalItem        `json:"evaluations"`
	Options     *BatchOptions          `json:"options,omitempty"`
}

// BatchEvaluationResponse is the result of a batch authorization check.
type BatchEvaluationResponse struct {
	Evaluations []AuthorizeResponse `json:"evaluations"`
}

// Delegation represents an active or revoked delegation record.
type Delegation struct {
	ID          string     `json:"id"`
	DelegateID  string     `json:"delegate_id"`
	DelegatorID string     `json:"delegator_id"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreateDelegationRequest creates a delegation so that delegate acts on behalf of delegator.
type CreateDelegationRequest struct {
	DelegateID  string     `json:"delegate_id"`
	DelegatorID string     `json:"delegator_id"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
