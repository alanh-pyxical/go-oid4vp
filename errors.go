// Package oid4vp implements OpenID for Verifiable Presentations (OID4VP,
// draft-ietf-oauth-selective-disclosure-jwt).
//
// The package is split into two sub-packages by role:
//
//   - [verifier] creates authorization requests, exposes an http.Handler for
//     the response_uri endpoint, and validates VP Token responses.
//   - [holder] receives authorization requests, selects matching credentials,
//     and constructs VP Token presentations.
//
// The [types] sub-package defines the shared protocol types.
package oid4vp

import (
	"errors"
	"fmt"
)

// Sentinel errors. Use [errors.Is] to test for these.
var (
	// ErrSessionNotFound is returned when the verifier cannot find a session
	// matching the state parameter in a response.
	ErrSessionNotFound = errors.New("oid4vp: session not found")

	// ErrSessionExpired is returned when the verification session has timed
	// out before the holder responded.
	ErrSessionExpired = errors.New("oid4vp: session expired")

	// ErrNoMatchingCredential is returned by the holder selector when no
	// stored credential satisfies a given InputDescriptor.
	ErrNoMatchingCredential = errors.New("oid4vp: no credential satisfies input descriptor")

	// ErrMissingSubmission is returned when a VP Token response arrives
	// without a presentation_submission.
	ErrMissingSubmission = errors.New("oid4vp: presentation_submission is required")

	// ErrSubmissionMismatch is returned when the presentation_submission
	// references a definition_id that does not match the active session.
	ErrSubmissionMismatch = errors.New("oid4vp: presentation_submission definition_id mismatch")

	// ErrCredentialValidationFailed is returned when a CredentialValidator
	// rejects one of the presented credentials.
	ErrCredentialValidationFailed = errors.New("oid4vp: credential validation failed")

	// ErrDefinitionFetchFailed is returned when the holder cannot retrieve
	// a PresentationDefinition from a presentation_definition_uri.
	ErrDefinitionFetchFailed = errors.New("oid4vp: fetching presentation definition failed")

	// ErrRequestDecodeFailed is returned when the holder cannot parse an
	// authorization request.
	ErrRequestDecodeFailed = errors.New("oid4vp: decoding authorization request failed")
)

// FieldError records a constraint failure for a specific JSONPath field within
// a credential, giving the holder and verifier actionable diagnostics.
type FieldError struct {
	// DescriptorID is the InputDescriptor.ID that failed.
	DescriptorID string

	// Path is the JSONPath expression that failed.
	Path string

	// Err is the underlying reason (e.g. field absent, filter mismatch).
	Err error
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("oid4vp: descriptor %q field %q: %v", e.DescriptorID, e.Path, e.Err)
}

func (e *FieldError) Unwrap() error { return e.Err }

// ValidationError records a complete VP Token validation failure with enough
// context for audit logging.
type ValidationError struct {
	// Stage names the step that failed, e.g. "submission_parse",
	// "credential_verify", "field_constraint".
	Stage string

	// DescriptorID is the InputDescriptor.ID being evaluated when the
	// failure occurred. Empty for failures not tied to a specific descriptor.
	DescriptorID string

	// Err is the underlying cause.
	Err error
}

func (e *ValidationError) Error() string {
	if e.DescriptorID != "" {
		return fmt.Sprintf("oid4vp: validation failed at %s (descriptor %q): %v",
			e.Stage, e.DescriptorID, e.Err)
	}
	return fmt.Sprintf("oid4vp: validation failed at %s: %v", e.Stage, e.Err)
}

func (e *ValidationError) Unwrap() error { return e.Err }
