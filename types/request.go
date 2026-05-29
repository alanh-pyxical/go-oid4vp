package types

// AuthorizationRequest is the OID4VP request sent from verifier to holder.
// It may be delivered inline (as query parameters), as a request object JWT
// (request=), or by reference (request_uri=).
//
// Defined in OID4VP §5.
type AuthorizationRequest struct {
	// ResponseType must be "vp_token" for OID4VP. Required.
	ResponseType string `json:"response_type"`

	// ClientID is the verifier's identifier. Required.
	// For direct_post response mode, this is the verifier's HTTPS URI.
	ClientID string `json:"client_id"`

	// ResponseMode controls how the holder returns the VP Token.
	// "direct_post" sends a POST to ResponseURI. Required.
	ResponseMode string `json:"response_mode"`

	// ResponseURI is the endpoint to which the holder POSTs the VP Token.
	// Required when ResponseMode is "direct_post".
	ResponseURI string `json:"response_uri"`

	// PresentationDefinition describes what credentials the verifier needs.
	// Either this or PresentationDefinitionURI must be set.
	PresentationDefinition *PresentationDefinition `json:"presentation_definition,omitempty"`

	// PresentationDefinitionURI is a URL from which the holder fetches the
	// PresentationDefinition. Alternative to embedding it inline.
	PresentationDefinitionURI string `json:"presentation_definition_uri,omitempty"`

	// Nonce is a fresh random value the holder must include in the KB-JWT
	// to prevent replay. Required.
	Nonce string `json:"nonce"`

	// State is an opaque value the verifier uses to correlate the request
	// with the response. Optional but recommended.
	State string `json:"state,omitempty"`

	// ClientMetadata carries optional verifier display metadata shown to
	// the user in the wallet.
	ClientMetadata *ClientMetadata `json:"client_metadata,omitempty"`
}

// ClientMetadata carries display and policy metadata about the verifier,
// shown to the user by the wallet during the consent step.
type ClientMetadata struct {
	// Name is the verifier's display name.
	Name string `json:"client_name,omitempty"`

	// LogoURI is the verifier's logo, displayed in the wallet consent UI.
	LogoURI string `json:"logo_uri,omitempty"`

	// PolicyURI links to the verifier's privacy policy.
	PolicyURI string `json:"policy_uri,omitempty"`

	// VPFormats lists the VP formats the verifier accepts. Keyed by
	// format identifier, e.g. "vc+sd-jwt".
	VPFormats map[string]FormatConstraint `json:"vp_formats,omitempty"`
}

// AuthorizationResponse is POSTed by the holder to the verifier's ResponseURI
// when ResponseMode is "direct_post".
type AuthorizationResponse struct {
	// VPToken is the Verifiable Presentation Token. For SD-JWT-VC this is
	// the full tilde-separated presentation string including KB-JWT.
	// When multiple credentials are presented, this is a JSON array of
	// presentation strings.
	VPToken string `json:"vp_token"`

	// PresentationSubmission maps the VPToken back to the
	// PresentationDefinition, telling the verifier which credential in the
	// token satisfies which InputDescriptor.
	PresentationSubmission *PresentationSubmission `json:"presentation_submission"`

	// State echoes the state from the AuthorizationRequest.
	State string `json:"state,omitempty"`
}

// PresentationSubmission describes how the submitted VPToken satisfies the
// PresentationDefinition. Defined in Presentation Exchange §6.
type PresentationSubmission struct {
	// ID is a unique identifier for this submission.
	ID string `json:"id"`

	// DefinitionID references the PresentationDefinition.ID this satisfies.
	DefinitionID string `json:"definition_id"`

	// DescriptorMap maps each InputDescriptor to the credential that
	// satisfies it within the VPToken.
	DescriptorMap []DescriptorMapEntry `json:"descriptor_map"`
}

// DescriptorMapEntry maps one InputDescriptor to the path within the VPToken
// where the satisfying credential can be found.
type DescriptorMapEntry struct {
	// ID references an InputDescriptor.ID from the PresentationDefinition.
	ID string `json:"id"`

	// Format is the format of the credential at Path.
	Format string `json:"format"`

	// Path is a JSONPath expression locating the credential within the
	// VPToken. "$" means the VPToken itself is the credential (single
	// credential case).
	Path string `json:"path"`
}

// DirectPostRequest is the form body sent to the verifier's response_uri
// endpoint. Fields match AuthorizationResponse but serialised as
// application/x-www-form-urlencoded or application/json.
type DirectPostRequest struct {
	VPToken                string `json:"vp_token"`
	PresentationSubmission string `json:"presentation_submission"` // JSON-encoded
	State                  string `json:"state,omitempty"`
}

// ResponseModeDirectPost is the only response mode currently implemented.
const ResponseModeDirectPost = "direct_post"

// ResponseTypeVPToken is the response_type value for OID4VP.
const ResponseTypeVPToken = "vp_token"
