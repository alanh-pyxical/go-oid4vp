// Package holder implements the holder role in OID4VP. It receives
// authorization requests, selects stored credentials that satisfy the
// PresentationDefinition, and constructs a VP Token response.
//
// The holder is credential-format agnostic. Callers supply [Presenter]
// implementations — one per format — that know how to produce a presentation
// from a stored credential. For SD-JWT-VC credentials, wire in go-sd-jwt-vc's
// Holder here.
package holder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	oid4vp "github.com/alanh-pyxical/go-oid4vp"
	"github.com/alanh-pyxical/go-oid4vp/types"
	"github.com/google/uuid"
)

// StoredCredential is the holder's view of a credential in the wallet.
type StoredCredential struct {
	// ID is the wallet's internal reference for this credential.
	ID string

	// Format is the credential format, e.g. "vc+sd-jwt".
	Format string

	// Raw is the full credential string (e.g. SD-JWT-VC with all disclosures).
	Raw string

	// Claims is a flat map of the credential's claims, used for matching
	// against PresentationDefinition constraints at selection time.
	Claims map[string]any

	// VCT is the Verifiable Credential Type for SD-JWT-VC credentials.
	VCT string
}

// Presenter constructs a presentation from a stored credential.
// Implement this using go-sd-jwt-vc's Holder for SD-JWT-VC credentials.
type Presenter interface {
	// Format returns the credential format this presenter handles.
	Format() string

	// Present builds a presentation string, revealing only revealClaims.
	// nonce and audience come from the AuthorizationRequest and anchor
	// the KB-JWT to this specific verifier exchange.
	Present(ctx context.Context, raw, nonce, audience string, revealClaims []string) (string, error)
}

// Match records that a StoredCredential satisfies an InputDescriptor.
type Match struct {
	// DescriptorID is the InputDescriptor.ID this match satisfies.
	DescriptorID string

	// Credential is the matching stored credential.
	Credential *StoredCredential

	// SatisfiedPaths lists the JSONPath expressions that matched.
	SatisfiedPaths []string

	// SuggestedRevealClaims is the minimal claim set needed to satisfy
	// the descriptor's field constraints. The wallet may expand this.
	SuggestedRevealClaims []string
}

// Holder constructs VP Token presentations. Construct one with [New].
// A Holder is safe for concurrent use.
type Holder struct {
	presenters map[string]Presenter
	httpClient *http.Client
}

// Option configures a [Holder].
type Option func(*Holder)

// WithHTTPClient sets the HTTP client for fetching remote PresentationDefinitions.
func WithHTTPClient(c *http.Client) Option {
	return func(h *Holder) { h.httpClient = c }
}

// New creates a Holder. presenters is one Presenter per credential format.
func New(presenters []Presenter, opts ...Option) *Holder {
	pm := make(map[string]Presenter, len(presenters))
	for _, p := range presenters {
		pm[p.Format()] = p
	}
	h := &Holder{presenters: pm, httpClient: http.DefaultClient}
	for _, o := range opts {
		o(h)
	}
	return h
}

// ParseRequest decodes an OID4VP authorization request from either a plain
// JSON string or an openid4vp:// URI. Fetches a remote PresentationDefinition
// if the request uses presentation_definition_uri.
func (h *Holder) ParseRequest(ctx context.Context, raw string) (*types.AuthorizationRequest, error) {
	var req types.AuthorizationRequest

	if strings.HasPrefix(raw, "openid4vp://") {
		parts := strings.SplitN(raw, "?", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w: missing query in openid4vp URI", oid4vp.ErrRequestDecodeFailed)
		}
		vals, err := url.ParseQuery(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w: parsing URI query: %v", oid4vp.ErrRequestDecodeFailed, err)
		}
		reqJSON := vals.Get("request")
		if reqJSON == "" {
			return nil, fmt.Errorf("%w: no request parameter in URI", oid4vp.ErrRequestDecodeFailed)
		}
		if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
			return nil, fmt.Errorf("%w: %v", oid4vp.ErrRequestDecodeFailed, err)
		}
	} else {
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			return nil, fmt.Errorf("%w: %v", oid4vp.ErrRequestDecodeFailed, err)
		}
	}

	if req.PresentationDefinition == nil && req.PresentationDefinitionURI != "" {
		def, err := h.fetchDefinition(ctx, req.PresentationDefinitionURI)
		if err != nil {
			return nil, err
		}
		req.PresentationDefinition = def
	}

	if req.PresentationDefinition == nil {
		return nil, fmt.Errorf("%w: no presentation_definition", oid4vp.ErrRequestDecodeFailed)
	}
	return &req, nil
}

// SelectCredentials matches the wallet's stored credentials against a
// PresentationDefinition. Returns one Match per InputDescriptor using the
// first credential that satisfies each, plus one error per unsatisfied
// descriptor.
func (h *Holder) SelectCredentials(
	def *types.PresentationDefinition,
	wallet []StoredCredential,
) ([]Match, []error) {
	var matches []Match
	var errs []error

	for _, desc := range def.InputDescriptors {
		m, err := h.matchDescriptor(desc, wallet)
		if err != nil {
			errs = append(errs, fmt.Errorf("descriptor %q: %w", desc.ID, err))
			continue
		}
		matches = append(matches, *m)
	}
	return matches, errs
}

// BuildResponse constructs the VP Token and PresentationSubmission from the
// selected matches. revealOverride (keyed by DescriptorID) lets the wallet
// user override the suggested claim set.
func (h *Holder) BuildResponse(
	ctx context.Context,
	req *types.AuthorizationRequest,
	matches []Match,
	revealOverride map[string][]string,
) (*types.AuthorizationResponse, error) {

	if len(matches) == 0 {
		return nil, fmt.Errorf("oid4vp/holder: no credential matches provided")
	}

	presentations := make([]string, 0, len(matches))
	for _, m := range matches {
		reveal := m.SuggestedRevealClaims
		if revealOverride != nil {
			if r, ok := revealOverride[m.DescriptorID]; ok {
				reveal = r
			}
		}

		presenter, ok := h.presenters[m.Credential.Format]
		if !ok {
			return nil, fmt.Errorf("oid4vp/holder: no presenter for format %q", m.Credential.Format)
		}

		presented, err := presenter.Present(ctx, m.Credential.Raw, req.Nonce, req.ClientID, reveal)
		if err != nil {
			return nil, fmt.Errorf("oid4vp/holder: presenting %q: %w", m.DescriptorID, err)
		}
		presentations = append(presentations, presented)
	}

	submission := &types.PresentationSubmission{
		ID:           uuid.New().String(),
		DefinitionID: req.PresentationDefinition.ID,
	}

	var vpToken string
	if len(presentations) == 1 {
		vpToken = presentations[0]
		submission.DescriptorMap = []types.DescriptorMapEntry{{
			ID:     matches[0].DescriptorID,
			Format: matches[0].Credential.Format,
			Path:   "$",
		}}
	} else {
		b, err := json.Marshal(presentations)
		if err != nil {
			return nil, fmt.Errorf("oid4vp/holder: encoding vp_token array: %w", err)
		}
		vpToken = string(b)
		for i, m := range matches {
			submission.DescriptorMap = append(submission.DescriptorMap, types.DescriptorMapEntry{
				ID:     m.DescriptorID,
				Format: m.Credential.Format,
				Path:   fmt.Sprintf("$[%d]", i),
			})
		}
	}

	return &types.AuthorizationResponse{
		VPToken:                vpToken,
		PresentationSubmission: submission,
		State:                  req.State,
	}, nil
}

// Submit POSTs the VP Token response to the verifier's response_uri.
func (h *Holder) Submit(ctx context.Context, responseURI string, resp *types.AuthorizationResponse) error {
	psJSON, err := json.Marshal(resp.PresentationSubmission)
	if err != nil {
		return fmt.Errorf("oid4vp/holder: encoding submission: %w", err)
	}
	body, err := json.Marshal(map[string]string{
		"vp_token":                resp.VPToken,
		"presentation_submission": string(psJSON),
		"state":                   resp.State,
	})
	if err != nil {
		return fmt.Errorf("oid4vp/holder: encoding body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI,
		strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("oid4vp/holder: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	hresp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("oid4vp/holder: posting response: %w", err)
	}
	defer hresp.Body.Close()

	if hresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(hresp.Body)
		return fmt.Errorf("oid4vp/holder: verifier returned HTTP %d: %s", hresp.StatusCode, b)
	}
	return nil
}

// --- internal ---

func (h *Holder) matchDescriptor(desc types.InputDescriptor, wallet []StoredCredential) (*Match, error) {
	for i := range wallet {
		cred := &wallet[i]

		// Format filter.
		if len(desc.Format) > 0 {
			if _, ok := desc.Format[cred.Format]; !ok {
				continue
			}
		}

		// Field constraints.
		if desc.Constraints != nil {
			ok, satisfied, suggested := checkCredentialFields(cred, desc.Constraints.Fields)
			if !ok {
				continue
			}
			return &Match{
				DescriptorID:          desc.ID,
				Credential:            cred,
				SatisfiedPaths:        satisfied,
				SuggestedRevealClaims: suggested,
			}, nil
		}

		// No constraints — any credential of the right format matches.
		return &Match{
			DescriptorID: desc.ID,
			Credential:   cred,
		}, nil
	}
	return nil, oid4vp.ErrNoMatchingCredential
}

// checkCredentialFields checks whether cred.Claims satisfies fields.
// Returns (allSatisfied, matchedPaths, claimsToReveal).
func checkCredentialFields(cred *StoredCredential, fields []types.Field) (bool, []string, []string) {
	var matched []string
	var reveal []string

	for _, field := range fields {
		if field.Optional {
			continue
		}
		found := false
		for _, p := range field.Path {
			name := strings.TrimPrefix(p, "$.")
			if name == p {
				continue // not a simple $.name path
			}
			if v, ok := cred.Claims[name]; ok {
				// If a filter is set, check it.
				if field.Filter != nil {
					if !filterMatches(v, field.Filter) {
						continue
					}
				}
				matched = append(matched, p)
				reveal = append(reveal, name)
				found = true
				break
			}
		}
		if !found {
			return false, nil, nil
		}
	}
	return true, matched, reveal
}

// filterMatches is a lightweight pre-check used during credential selection.
// It checks const and enum filters; other filter types are left to the
// verifier's full constraint check.
func filterMatches(value any, f *types.Filter) bool {
	if f.Const != nil {
		va, _ := json.Marshal(value)
		fb, _ := json.Marshal(f.Const)
		return string(va) == string(fb)
	}
	if len(f.Enum) > 0 {
		va, _ := json.Marshal(value)
		for _, e := range f.Enum {
			if eb, _ := json.Marshal(e); string(va) == string(eb) {
				return true
			}
		}
		return false
	}
	return true
}

func (h *Holder) fetchDefinition(ctx context.Context, uri string) (*types.PresentationDefinition, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", oid4vp.ErrDefinitionFetchFailed, err)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", oid4vp.ErrDefinitionFetchFailed, err)
	}
	defer resp.Body.Close()

	var def types.PresentationDefinition
	if err := json.NewDecoder(resp.Body).Decode(&def); err != nil {
		return nil, fmt.Errorf("%w: decoding: %v", oid4vp.ErrDefinitionFetchFailed, err)
	}
	return &def, nil
}
