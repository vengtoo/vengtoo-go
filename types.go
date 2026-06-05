package vengtoo

// Subject represents the entity performing the action.
type Subject struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Roles      []string               `json:"roles,omitempty"`
}

// Resource represents the target of the action.
type Resource struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
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
