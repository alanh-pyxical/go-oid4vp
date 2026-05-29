// Package verifier implements the verifier role in OID4VP. It creates
// authorization requests, exposes an [http.Handler] for the response_uri
// endpoint, and validates VP Token responses against the original
// PresentationDefinition.
//
// Callers provide:
//   - A [SessionStore] to persist verification sessions between the request
//     and the response (the holder may take seconds or minutes to respond).
//   - One or more [CredentialValidator] implementations to verify the
//     cryptographic integrity of presented credentials.
package verifier

import (
	"context"
	"time"

	"github.com/alanh-pyxical/go-oid4vp/types"
)

// VerificationSession holds the state the verifier needs to correlate an
// authorization request with a subsequent VP Token response.
//
// Sessions are keyed by State (the OAuth 2.0 state parameter), which is
// included in both the request and the response.
type VerificationSession struct {
	// State is the correlation key — a random value included in the
	// authorization request and echoed in the response.
	State string

	// Nonce is the challenge the holder must include in the KB-JWT.
	Nonce string

	// Definition is the PresentationDefinition sent in the request.
	Definition *types.PresentationDefinition

	// ResponseURI is the endpoint to which the holder will POST.
	ResponseURI string

	// CreatedAt records when this session was opened.
	CreatedAt time.Time

	// ExpiresAt is when this session expires. After this point the verifier
	// will reject responses that reference it.
	ExpiresAt time.Time

	// Result is populated once the holder has responded and the response
	// has been validated. Nil while the session is still pending.
	Result *VerificationResult
}

// IsPending reports whether the session is waiting for a response.
func (s *VerificationSession) IsPending() bool { return s.Result == nil }

// SessionStore persists and retrieves [VerificationSession] values.
// The library creates a session when it builds an authorization request and
// retrieves it when the holder's response arrives.
//
// Implementations must be safe for concurrent use.
type SessionStore interface {
	// Save persists a new session.
	Save(ctx context.Context, session *VerificationSession) error

	// Get retrieves a session by its State value. Returns
	// [oid4vp.ErrSessionNotFound] if unknown or
	// [oid4vp.ErrSessionExpired] if past ExpiresAt.
	Get(ctx context.Context, state string) (*VerificationSession, error)

	// Complete updates a session with its verification result.
	Complete(ctx context.Context, state string, result *VerificationResult) error
}

// VerificationResult is the output of a successful VP Token validation.
type VerificationResult struct {
	// DescriptorResults maps each InputDescriptor.ID to the claims extracted
	// from the credential that satisfied it.
	DescriptorResults map[string]*DescriptorResult

	// State echoes the session state value.
	State string
}

// DescriptorResult holds the validated claims for one InputDescriptor.
type DescriptorResult struct {
	// CredentialFormat is the format of the presented credential,
	// e.g. "vc+sd-jwt".
	CredentialFormat string

	// DisclosedClaims holds the claims the holder chose to reveal.
	// For SD-JWT-VC credentials this is the subset of selectively
	// disclosable claims that were included in the presentation.
	DisclosedClaims map[string]any

	// AllClaims holds all claims from the issuer JWT, including those
	// that are always disclosed (not selectively disclosed).
	AllClaims map[string]any

	// Issuer is the iss claim from the credential's issuer JWT.
	Issuer string

	// Subject is the sub claim, if present.
	Subject string

	// KeyBound is true when the presentation included a valid KB-JWT.
	KeyBound bool
}

// CredentialValidator validates a single presented credential and returns the
// claims it contains. Callers supply one validator per credential format they
// accept.
//
// For SD-JWT-VC credentials, wire in go-sd-jwt-vc's Verifier here.
type CredentialValidator interface {
	// Format returns the credential format this validator handles,
	// e.g. "vc+sd-jwt". The verifier routes each credential to the
	// appropriate validator by format.
	Format() string

	// Validate verifies the credential and returns a DescriptorResult
	// populated with the verified claims. nonce and audience are the
	// values from the current verification session, used to check the
	// KB-JWT.
	Validate(ctx context.Context, credential, nonce, audience string) (*DescriptorResult, error)
}
