package oid4vp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oid4vp "github.com/alanh-pyxical/go-oid4vp"
	"github.com/alanh-pyxical/go-oid4vp/holder"
	"github.com/alanh-pyxical/go-oid4vp/types"
	"github.com/alanh-pyxical/go-oid4vp/verifier"
)

// --- test doubles ---

// mockPresenter is a Presenter that returns the raw credential unchanged,
// simulating what go-sd-jwt-vc's Holder would produce.
type mockPresenter struct {
	format string
}

func (p *mockPresenter) Format() string { return p.format }

func (p *mockPresenter) Present(_ context.Context, raw, _, _ string, _ []string) (string, error) {
	return raw, nil
}

// mockValidator is a CredentialValidator that accepts any credential string
// and returns a fixed set of claims.
type mockValidator struct {
	format string
	claims map[string]any
}

func (v *mockValidator) Format() string { return v.format }

func (v *mockValidator) Validate(_ context.Context, _, _, _ string) (*verifier.DescriptorResult, error) {
	all := make(map[string]any, len(v.claims))
	for k, val := range v.claims {
		all[k] = val
	}
	return &verifier.DescriptorResult{
		CredentialFormat: v.format,
		DisclosedClaims:  all,
		AllClaims:        all,
		Issuer:           "https://bank.example",
		KeyBound:         true,
	}, nil
}

// --- helpers ---

func buildVerifier(t *testing.T, serverURL string, claims map[string]any) (*verifier.Verifier, *httptest.Server) {
	t.Helper()

	responseURI := serverURL + "/vp/response"
	v, err := verifier.New(
		serverURL,
		responseURI,
		verifier.NewMemorySessionStore(),
		[]verifier.CredentialValidator{
			&mockValidator{format: "vc+sd-jwt", claims: claims},
		},
	)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}
	return v, nil
}

// --- tests ---

func TestNewRequest_CreatesSession(t *testing.T) {
	store := verifier.NewMemorySessionStore()
	v, err := verifier.New(
		"https://conveyancer.example",
		"https://conveyancer.example/vp/response",
		store,
		[]verifier.CredentialValidator{&mockValidator{format: "vc+sd-jwt"}},
	)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	def := mortgageDefinition()
	req, err := v.NewRequest(context.Background(), verifier.RequestConfig{
		Definition: def,
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if req.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
	if req.State == "" {
		t.Error("expected non-empty state")
	}
	if req.ResponseURI != "https://conveyancer.example/vp/response" {
		t.Errorf("ResponseURI: got %q", req.ResponseURI)
	}
	if req.PresentationDefinition.ID != def.ID {
		t.Errorf("definition ID mismatch")
	}
}

func TestRequestURI_RoundTrip(t *testing.T) {
	v, err := verifier.New(
		"https://conveyancer.example",
		"https://conveyancer.example/vp/response",
		verifier.NewMemorySessionStore(),
		[]verifier.CredentialValidator{&mockValidator{format: "vc+sd-jwt"}},
	)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	req, _ := v.NewRequest(context.Background(), verifier.RequestConfig{
		Definition: mortgageDefinition(),
	})

	uri, err := verifier.RequestURI(req)
	if err != nil {
		t.Fatalf("RequestURI: %v", err)
	}
	if !strings.HasPrefix(uri, "openid4vp://") {
		t.Errorf("expected openid4vp:// URI, got %q", uri[:min(len(uri), 30)])
	}

	// Holder parses it back.
	h := holder.New([]holder.Presenter{&mockPresenter{format: "vc+sd-jwt"}})
	parsed, err := h.ParseRequest(context.Background(), uri)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed.Nonce != req.Nonce {
		t.Errorf("nonce mismatch: got %q, want %q", parsed.Nonce, req.Nonce)
	}
	if parsed.State != req.State {
		t.Errorf("state mismatch")
	}
}

func TestSelectCredentials_Match(t *testing.T) {
	h := holder.New([]holder.Presenter{&mockPresenter{format: "vc+sd-jwt"}})

	wallet := []holder.StoredCredential{
		{
			ID:     "cred-1",
			Format: "vc+sd-jwt",
			Raw:    "eyJ.mock.credential",
			VCT:    "https://schema.pyxical.com/MortgageOffer",
			Claims: map[string]any{
				"vct":          "https://schema.pyxical.com/MortgageOffer",
				"bank_name":    "Lloyds Bank plc",
				"offer_expiry": "2025-10-01",
				"max_amount":   450000.0,
			},
		},
	}

	matches, errs := h.SelectCredentials(mortgageDefinition(), wallet)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].DescriptorID != "mortgage-offer" {
		t.Errorf("DescriptorID: got %q", matches[0].DescriptorID)
	}
}

func TestSelectCredentials_NoMatch(t *testing.T) {
	h := holder.New([]holder.Presenter{&mockPresenter{format: "vc+sd-jwt"}})

	wallet := []holder.StoredCredential{
		{
			ID:     "cred-1",
			Format: "vc+sd-jwt",
			VCT:    "SomeOtherCredential",
			Claims: map[string]any{"vct": "SomeOtherCredential"},
		},
	}

	_, errs := h.SelectCredentials(mortgageDefinition(), wallet)
	if len(errs) == 0 {
		t.Fatal("expected an error for unmatched descriptor")
	}
	if !isErr(errs[0], oid4vp.ErrNoMatchingCredential) {
		t.Errorf("expected ErrNoMatchingCredential, got %v", errs[0])
	}
}

func TestFullFlow_VerifierHolderVerifier(t *testing.T) {
	ctx := context.Background()

	claims := map[string]any{
		"vct":          "https://schema.pyxical.com/MortgageOffer",
		"bank_name":    "Lloyds Bank plc",
		"offer_expiry": "2025-10-01",
	}

	// Build the verifier with a test HTTP server.
	sessionStore := verifier.NewMemorySessionStore()
	var v *verifier.Verifier

	// Start the test server first, then build the verifier with the URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()

	var err error
	v, err = verifier.New(
		srv.URL,
		srv.URL+"/vp/response",
		sessionStore,
		[]verifier.CredentialValidator{
			&mockValidator{format: "vc+sd-jwt", claims: claims},
		},
	)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}

	// 1. Verifier creates an authorization request.
	req, err := v.NewRequest(ctx, verifier.RequestConfig{
		Definition: mortgageDefinition(),
	})
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	reqJSON, _ := json.Marshal(req)

	// 2. Holder parses the request and builds a response.
	h := holder.New(
		[]holder.Presenter{&mockPresenter{format: "vc+sd-jwt"}},
		holder.WithHTTPClient(srv.Client()),
	)

	parsedReq, err := h.ParseRequest(ctx, string(reqJSON))
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	wallet := []holder.StoredCredential{{
		ID:     "cred-1",
		Format: "vc+sd-jwt",
		Raw:    "eyJ.mock.credential~disc1~kbJWT",
		VCT:    "https://schema.pyxical.com/MortgageOffer",
		Claims: claims,
	}}

	matches, errs := h.SelectCredentials(parsedReq.PresentationDefinition, wallet)
	if len(errs) > 0 {
		t.Fatalf("SelectCredentials errors: %v", errs)
	}

	response, err := h.BuildResponse(ctx, parsedReq, matches, nil)
	if err != nil {
		t.Fatalf("BuildResponse: %v", err)
	}

	// 3. Holder submits to the verifier.
	if err := h.Submit(ctx, srv.URL+"/vp/response", response); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// 4. Verifier polls for the result.
	result, err := v.PollResult(ctx, req.State)
	if err != nil {
		t.Fatalf("PollResult: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	descResult, ok := result.DescriptorResults["mortgage-offer"]
	if !ok {
		t.Fatal("expected descriptor result for 'mortgage-offer'")
	}
	if descResult.Issuer != "https://bank.example" {
		t.Errorf("Issuer: got %q", descResult.Issuer)
	}
	if !descResult.KeyBound {
		t.Error("expected KeyBound=true")
	}
}

func TestVerifier_SessionExpiry(t *testing.T) {
	store := verifier.NewMemorySessionStore()
	v, _ := verifier.New(
		"https://verifier.example",
		"https://verifier.example/vp/response",
		store,
		[]verifier.CredentialValidator{&mockValidator{format: "vc+sd-jwt"}},
		verifier.WithSessionTTL(0), // expires immediately
	)

	req, _ := v.NewRequest(context.Background(), verifier.RequestConfig{
		Definition: mortgageDefinition(),
	})

	// Attempting to retrieve the result should report session expired.
	_, err := v.PollResult(context.Background(), req.State)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	if !isErr(err, oid4vp.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestVerifier_SubmissionMismatch(t *testing.T) {
	ctx := context.Background()
	store := verifier.NewMemorySessionStore()
	v, _ := verifier.New(
		"https://verifier.example",
		"https://verifier.example/vp/response",
		store,
		[]verifier.CredentialValidator{&mockValidator{format: "vc+sd-jwt"}},
	)

	req, _ := v.NewRequest(ctx, verifier.RequestConfig{Definition: mortgageDefinition()})

	// Submit with a mismatched definition_id.
	badSubmission := &types.PresentationSubmission{
		ID:           "sub-1",
		DefinitionID: "wrong-definition-id",
		DescriptorMap: []types.DescriptorMapEntry{
			{ID: "mortgage-offer", Format: "vc+sd-jwt", Path: "$"},
		},
	}

	_, err := v.ValidateResponse(ctx, "eyJ.cred.sig", badSubmission, req.State)
	if err == nil {
		t.Fatal("expected error for mismatched submission")
	}
	if !isErr(err, oid4vp.ErrSubmissionMismatch) {
		t.Errorf("expected ErrSubmissionMismatch, got %v", err)
	}
}

// --- test fixtures ---

func mortgageDefinition() *types.PresentationDefinition {
	vctValue := any("https://schema.pyxical.com/MortgageOffer")
	return &types.PresentationDefinition{
		ID:      "mortgage-check-v1",
		Purpose: "Verify mortgage offer for property purchase",
		InputDescriptors: []types.InputDescriptor{
			{
				ID:   "mortgage-offer",
				Name: "Mortgage Offer",
				Format: map[string]types.FormatConstraint{
					"vc+sd-jwt": {},
				},
				Constraints: &types.Constraints{
					Fields: []types.Field{
						{
							Path:   []string{"$.vct"},
							Filter: &types.Filter{Const: vctValue},
						},
						{
							Path: []string{"$.bank_name"},
						},
						{
							Path: []string{"$.offer_expiry"},
						},
					},
				},
			},
		},
	}
}

func isErr(err, target error) bool {
	if err == target {
		return true
	}
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return isErr(u.Unwrap(), target)
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
