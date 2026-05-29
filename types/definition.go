// Package types defines the protocol types shared between the verifier and
// holder sub-packages. They map directly to the JSON structures defined in
// OpenID for Verifiable Presentations (OID4VP,
// draft-ietf-oauth-selective-disclosure-jwt) and the Presentation Exchange
// specification (https://identity.foundation/presentation-exchange/).
package types

// PresentationDefinition describes what a verifier needs from a holder.
// It is sent to the holder as part of the Authorization Request and defines
// one or more credential requirements via InputDescriptors.
//
// Defined in Presentation Exchange §2.
type PresentationDefinition struct {
	// ID is a unique identifier for this definition. Required.
	ID string `json:"id"`

	// Name is an optional human-readable label.
	Name string `json:"name,omitempty"`

	// Purpose describes why the verifier is requesting the credential.
	// Shown to the user in the wallet UI.
	Purpose string `json:"purpose,omitempty"`

	// InputDescriptors describes the credentials required. Each descriptor
	// represents one required credential; all must be satisfied.
	InputDescriptors []InputDescriptor `json:"input_descriptors"`

	// SubmissionRequirements, if present, allows complex combinatorial
	// rules over InputDescriptors (AND/OR groups). Omit for the simple
	// case where all descriptors must be satisfied.
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
}

// InputDescriptor describes a single credential requirement within a
// PresentationDefinition.
type InputDescriptor struct {
	// ID uniquely identifies this descriptor within the definition. Required.
	ID string `json:"id"`

	// Name is an optional human-readable label.
	Name string `json:"name,omitempty"`

	// Purpose describes why this specific credential is needed.
	Purpose string `json:"purpose,omitempty"`

	// Format restricts the acceptable credential formats. Keyed by format
	// identifier (e.g. "vc+sd-jwt"). Omit to accept any format.
	Format map[string]FormatConstraint `json:"format,omitempty"`

	// Constraints defines the field-level requirements the credential must
	// satisfy.
	Constraints *Constraints `json:"constraints,omitempty"`
}

// FormatConstraint lists the algorithms accepted for a given credential format.
type FormatConstraint struct {
	// AlgValuesSupported lists the JWA algorithm identifiers accepted.
	AlgValuesSupported []string `json:"alg_values_supported,omitempty"`
}

// Constraints holds the field-level requirements for an InputDescriptor.
type Constraints struct {
	// Fields lists the individual claim path constraints. All fields with
	// Optional=false must be present and satisfy their filter.
	Fields []Field `json:"fields,omitempty"`

	// LimitDisclosure controls whether the holder may include only the
	// requested fields. "required" means the holder MUST use selective
	// disclosure. "preferred" is a hint.
	LimitDisclosure string `json:"limit_disclosure,omitempty"`
}

// Field specifies a constraint on a single claim within a credential.
type Field struct {
	// Path is a list of JSONPath expressions evaluated against the
	// credential's claims. The first path that resolves wins.
	// Example: ["$.offer_expiry", "$.validUntil"]
	Path []string `json:"path"`

	// ID is an optional stable identifier for this field constraint.
	ID string `json:"id,omitempty"`

	// Purpose describes why this field is needed.
	Purpose string `json:"purpose,omitempty"`

	// Filter is a JSON Schema fragment the field's value must satisfy.
	// Omit to require only presence.
	Filter *Filter `json:"filter,omitempty"`

	// Optional, if true, means the field need not be present. Defaults
	// to false (field is required).
	Optional bool `json:"optional,omitempty"`
}

// Filter is a JSON Schema fragment used to constrain a field's value.
type Filter struct {
	// Type is the JSON Schema type ("string", "number", "boolean", etc.).
	Type string `json:"type,omitempty"`

	// Const requires the value to equal exactly this.
	Const any `json:"const,omitempty"`

	// Enum requires the value to be one of these.
	Enum []any `json:"enum,omitempty"`

	// Pattern is a regex the string value must match.
	Pattern string `json:"pattern,omitempty"`

	// Minimum and Maximum apply to numeric values.
	Minimum *float64 `json:"minimum,omitempty"`
	Maximum *float64 `json:"maximum,omitempty"`

	// Format is a JSON Schema format constraint, e.g. "date".
	Format string `json:"format,omitempty"`
}

// SubmissionRequirement expresses combinatorial rules over InputDescriptors.
// Use for complex policies like "provide credential A OR (B AND C)".
type SubmissionRequirement struct {
	// Rule is "all" or "pick".
	Rule string `json:"rule"`

	// From references a group of InputDescriptors by their group tag.
	From string `json:"from,omitempty"`

	// Count is the exact number required (for Rule="pick").
	Count *int `json:"count,omitempty"`

	// Min and Max bound the number required.
	Min *int `json:"min,omitempty"`
	Max *int `json:"max,omitempty"`
}
