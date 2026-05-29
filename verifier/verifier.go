package verifier

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	oid4vp "github.com/alanh-pyxical/go-oid4vp"
	"github.com/alanh-pyxical/go-oid4vp/types"
	"github.com/google/uuid"
)

// Verifier manages the verifier side of OID4VP. Construct one with [New].
// A Verifier is safe for concurrent use.
type Verifier struct {
	clientID    string
	responseURI string
	sessions    SessionStore
	validators  map[string]CredentialValidator
	cfg         verifierConfig
}

type verifierConfig struct {
	sessionTTL     time.Duration
	clientMetadata *types.ClientMetadata
}

// Option configures a [Verifier].
type Option func(*verifierConfig)

// WithSessionTTL sets how long a verification session remains valid.
// Default: 5 minutes.
func WithSessionTTL(d time.Duration) Option {
	return func(c *verifierConfig) { c.sessionTTL = d }
}

// WithClientMetadata sets verifier display metadata shown in the wallet UI.
func WithClientMetadata(m *types.ClientMetadata) Option {
	return func(c *verifierConfig) { c.clientMetadata = m }
}

// New creates a Verifier.
//
//   - clientID:    the verifier's identifier (its HTTPS URI)
//   - responseURI: the endpoint holders POST VP Token responses to
//   - sessions:    persistence for verification sessions
//   - validators:  one per credential format accepted
func New(
	clientID string,
	responseURI string,
	sessions SessionStore,
	validators []CredentialValidator,
	opts ...Option,
) (*Verifier, error) {
	if clientID == "" {
		return nil, fmt.Errorf("oid4vp/verifier: clientID is required")
	}
	if responseURI == "" {
		return nil, fmt.Errorf("oid4vp/verifier: responseURI is required")
	}
	if len(validators) == 0 {
		return nil, fmt.Errorf("oid4vp/verifier: at least one CredentialValidator is required")
	}

	vm := make(map[string]CredentialValidator, len(validators))
	for _, v := range validators {
		vm[v.Format()] = v
	}

	cfg := verifierConfig{sessionTTL: 5 * time.Minute}
	for _, o := range opts {
		o(&cfg)
	}

	return &Verifier{
		clientID:    clientID,
		responseURI: responseURI,
		sessions:    sessions,
		validators:  vm,
		cfg:         cfg,
	}, nil
}

// RequestConfig carries the per-request parameters for [Verifier.NewRequest].
type RequestConfig struct {
	// Definition is required — it describes what credentials are needed.
	Definition *types.PresentationDefinition

	// State is the correlation token. A random UUID is used if empty.
	State string
}

// NewRequest creates an authorization request and the corresponding session.
// Deliver the returned AuthorizationRequest to the holder as a QR code,
// deep link, or request_uri.
func (v *Verifier) NewRequest(ctx context.Context, cfg RequestConfig) (*types.AuthorizationRequest, error) {
	if cfg.Definition == nil {
		return nil, fmt.Errorf("oid4vp/verifier: RequestConfig.Definition is required")
	}

	state := cfg.State
	if state == "" {
		state = uuid.New().String()
	}

	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("oid4vp/verifier: generating nonce: %w", err)
	}

	session := &VerificationSession{
		State:       state,
		Nonce:       nonce,
		Definition:  cfg.Definition,
		ResponseURI: v.responseURI,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(v.cfg.sessionTTL),
	}
	if err := v.sessions.Save(ctx, session); err != nil {
		return nil, fmt.Errorf("oid4vp/verifier: saving session: %w", err)
	}

	return &types.AuthorizationRequest{
		ResponseType:           types.ResponseTypeVPToken,
		ClientID:               v.clientID,
		ResponseMode:           types.ResponseModeDirectPost,
		ResponseURI:            v.responseURI,
		PresentationDefinition: cfg.Definition,
		Nonce:                  nonce,
		State:                  state,
		ClientMetadata:         v.cfg.clientMetadata,
	}, nil
}

// RequestURI encodes an AuthorizationRequest as an openid4vp:// URI.
func RequestURI(req *types.AuthorizationRequest) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("oid4vp/verifier: encoding request: %w", err)
	}
	return "openid4vp://?" + url.Values{"request": {string(b)}}.Encode(), nil
}

// Handler returns an [http.Handler] for the response_uri endpoint.
// Mount it at the path that corresponds to responseURI.
func (v *Verifier) Handler() http.Handler {
	return http.HandlerFunc(v.handleResponse)
}

// PollResult retrieves the result for state. Returns nil if still pending.
func (v *Verifier) PollResult(ctx context.Context, state string) (*VerificationResult, error) {
	session, err := v.sessions.Get(ctx, state)
	if err != nil {
		return nil, err
	}
	return session.Result, nil
}

func (v *Verifier) handleResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vpToken, submission, state, err := parseDirectPost(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := v.ValidateResponse(r.Context(), vpToken, submission, state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_vp_token", err.Error())
		return
	}

	if err := v.sessions.Complete(r.Context(), state, result); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "storing result")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ValidateResponse validates a VP Token response outside the HTTP handler.
// Useful when responses arrive via webhook or message queue.
func (v *Verifier) ValidateResponse(
	ctx context.Context,
	vpToken string,
	submission *types.PresentationSubmission,
	state string,
) (*VerificationResult, error) {

	session, err := v.sessions.Get(ctx, state)
	if err != nil {
		return nil, &oid4vp.ValidationError{Stage: "session_lookup", Err: err}
	}

	if submission == nil {
		return nil, &oid4vp.ValidationError{Stage: "submission_parse", Err: oid4vp.ErrMissingSubmission}
	}
	if submission.DefinitionID != session.Definition.ID {
		return nil, &oid4vp.ValidationError{Stage: "submission_match", Err: oid4vp.ErrSubmissionMismatch}
	}

	credsByDescriptor, err := extractCredentials(vpToken, submission)
	if err != nil {
		return nil, &oid4vp.ValidationError{Stage: "credential_extract", Err: err}
	}

	result := &VerificationResult{
		DescriptorResults: make(map[string]*DescriptorResult, len(session.Definition.InputDescriptors)),
		State:             state,
	}

	for _, desc := range session.Definition.InputDescriptors {
		credential, ok := credsByDescriptor[desc.ID]
		if !ok {
			return nil, &oid4vp.ValidationError{
				Stage:        "credential_extract",
				DescriptorID: desc.ID,
				Err:          oid4vp.ErrNoMatchingCredential,
			}
		}

		format := formatForDescriptor(desc, submission)
		validator, ok := v.validators[format]
		if !ok {
			return nil, &oid4vp.ValidationError{
				Stage:        "validator_lookup",
				DescriptorID: desc.ID,
				Err:          fmt.Errorf("no validator registered for format %q", format),
			}
		}

		descResult, err := validator.Validate(ctx, credential, session.Nonce, v.clientID)
		if err != nil {
			return nil, &oid4vp.ValidationError{
				Stage:        "credential_verify",
				DescriptorID: desc.ID,
				Err:          err,
			}
		}

		if desc.Constraints != nil {
			if err := checkConstraints(desc, descResult.AllClaims, descResult.DisclosedClaims); err != nil {
				return nil, &oid4vp.ValidationError{
					Stage:        "field_constraint",
					DescriptorID: desc.ID,
					Err:          err,
				}
			}
		}

		result.DescriptorResults[desc.ID] = descResult
	}

	return result, nil
}

// --- helpers ---

func parseDirectPost(r *http.Request) (vpToken string, submission *types.PresentationSubmission, state string, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			VPToken string `json:"vp_token"`
			PS      string `json:"presentation_submission"`
			State   string `json:"state"`
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &body); err != nil {
			return "", nil, "", fmt.Errorf("parsing JSON body: %w", err)
		}
		vpToken, state = body.VPToken, body.State
		if body.PS != "" {
			var ps types.PresentationSubmission
			if err := json.Unmarshal([]byte(body.PS), &ps); err != nil {
				return "", nil, "", fmt.Errorf("parsing presentation_submission: %w", err)
			}
			submission = &ps
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return "", nil, "", fmt.Errorf("parsing form: %w", err)
		}
		vpToken, state = r.FormValue("vp_token"), r.FormValue("state")
		if ps := r.FormValue("presentation_submission"); ps != "" {
			var s types.PresentationSubmission
			if err := json.Unmarshal([]byte(ps), &s); err != nil {
				return "", nil, "", fmt.Errorf("parsing presentation_submission: %w", err)
			}
			submission = &s
		}
	}
	if vpToken == "" {
		return "", nil, "", fmt.Errorf("vp_token is required")
	}
	if submission == nil {
		return "", nil, "", fmt.Errorf("presentation_submission is required")
	}
	return vpToken, submission, state, nil
}

func extractCredentials(vpToken string, sub *types.PresentationSubmission) (map[string]string, error) {
	out := make(map[string]string, len(sub.DescriptorMap))
	for _, entry := range sub.DescriptorMap {
		cred, err := jsonPathExtract(vpToken, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("descriptor %q path %q: %w", entry.ID, entry.Path, err)
		}
		out[entry.ID] = cred
	}
	return out, nil
}

// jsonPathExtract handles "$" (identity) and "$[N]" (array index).
func jsonPathExtract(value, path string) (string, error) {
	if path == "$" {
		return value, nil
	}
	if strings.HasPrefix(path, "$[") && strings.HasSuffix(path, "]") {
		var idx int
		if _, err := fmt.Sscan(path[2:len(path)-1], &idx); err != nil {
			return "", fmt.Errorf("non-integer array index in path %q", path)
		}
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(value), &arr); err != nil {
			return "", fmt.Errorf("vp_token is not an array for path %q", path)
		}
		if idx >= len(arr) {
			return "", fmt.Errorf("index %d out of range (len %d)", idx, len(arr))
		}
		var s string
		if err := json.Unmarshal(arr[idx], &s); err != nil {
			return string(arr[idx]), nil
		}
		return s, nil
	}
	return "", fmt.Errorf("unsupported JSONPath %q", path)
}

func formatForDescriptor(desc types.InputDescriptor, sub *types.PresentationSubmission) string {
	for _, e := range sub.DescriptorMap {
		if e.ID == desc.ID {
			return e.Format
		}
	}
	return ""
}

func checkConstraints(desc types.InputDescriptor, allClaims, disclosed map[string]any) error {
	for _, field := range desc.Constraints.Fields {
		if field.Optional {
			continue
		}
		var value any
		found := false
		for _, p := range field.Path {
			name := strings.TrimPrefix(p, "$.")
			if name == p {
				continue
			}
			if v, ok := disclosed[name]; ok {
				value, found = v, true
				break
			}
			if v, ok := allClaims[name]; ok {
				value, found = v, true
				break
			}
		}
		if !found {
			return &oid4vp.FieldError{
				DescriptorID: desc.ID,
				Path:         strings.Join(field.Path, "|"),
				Err:          fmt.Errorf("required field not present"),
			}
		}
		if field.Filter != nil {
			if err := checkFilter(value, field.Filter); err != nil {
				return &oid4vp.FieldError{
					DescriptorID: desc.ID,
					Path:         strings.Join(field.Path, "|"),
					Err:          err,
				}
			}
		}
	}
	return nil
}

func checkFilter(value any, f *types.Filter) error {
	if f.Const != nil {
		va, _ := json.Marshal(value)
		fb, _ := json.Marshal(f.Const)
		if string(va) != string(fb) {
			return fmt.Errorf("value %v does not match const %v", value, f.Const)
		}
	}
	if len(f.Enum) > 0 {
		va, _ := json.Marshal(value)
		for _, e := range f.Enum {
			if eb, _ := json.Marshal(e); string(va) == string(eb) {
				return nil
			}
		}
		return fmt.Errorf("value %v not in enum %v", value, f.Enum)
	}
	if f.Minimum != nil {
		if n, ok := toFloat(value); !ok || n < *f.Minimum {
			return fmt.Errorf("value %v below minimum %v", value, *f.Minimum)
		}
	}
	if f.Maximum != nil {
		if n, ok := toFloat(value); !ok || n > *f.Maximum {
			return fmt.Errorf("value %v above maximum %v", value, *f.Maximum)
		}
	}
	return nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc}) //nolint:errcheck
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
