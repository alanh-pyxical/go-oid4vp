// Command mortgage demonstrates the full OID4VP flow using an in-process
// HTTP test server.
//
// It simulates:
//  1. A conveyancer (verifier) creating an authorization request for a
//     mortgage offer credential.
//  2. An aggregator wallet (holder) selecting a matching credential,
//     constructing the VP Token, and submitting it.
//  3. The conveyancer retrieving and inspecting the verified claims.
//
// Run with: go run ./example/mortgage
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	oid4vp "github.com/alanh-pyxical/go-oid4vp"
	"github.com/alanh-pyxical/go-oid4vp/holder"
	"github.com/alanh-pyxical/go-oid4vp/types"
	"github.com/alanh-pyxical/go-oid4vp/verifier"
)

func main() {
	ctx := context.Background()

	// -----------------------------------------------------------------------
	// 1. Conveyancer sets up its verifier service.
	// -----------------------------------------------------------------------

	sessionStore := verifier.NewMemorySessionStore()

	// The SD-JWT-VC validator — in production this wraps go-sd-jwt-vc's
	// Verifier. Here we use a mock that returns pre-set claims.
	sdJWTValidator := &mortgageValidator{
		issuedClaims: map[string]any{
			"vct":           "https://schema.pyxical.com/MortgageOffer",
			"bank_name":     "Lloyds Bank plc",
			"offer_expiry":  "2025-10-01",
			"applicant_ref": "APP-2025-78291",
		},
	}

	// We need the server URL before building the verifier, so use a
	// placeholder and rebuild after the server starts.
	var conv *verifier.Verifier
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conv.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()

	var err error
	conv, err = verifier.New(
		srv.URL,                // clientID — the verifier's identifier
		srv.URL+"/vp/response", // responseURI — where holders POST responses
		sessionStore,
		[]verifier.CredentialValidator{sdJWTValidator},
		verifier.WithClientMetadata(&types.ClientMetadata{
			Name:    "Smith & Jones Conveyancers",
			LogoURI: "https://smithjones.example/logo.png",
		}),
	)
	must(err, "building verifier")

	fmt.Println("=== Conveyancer verifier running at", srv.URL, "===\n")

	// -----------------------------------------------------------------------
	// 2. Conveyancer builds an authorization request for a mortgage offer.
	// -----------------------------------------------------------------------

	vctValue := any("https://schema.pyxical.com/MortgageOffer")
	def := &types.PresentationDefinition{
		ID:      "mortgage-check-v1",
		Purpose: "Verify mortgage offer for property purchase at 42 Acacia Avenue",
		InputDescriptors: []types.InputDescriptor{
			{
				ID:   "mortgage-offer",
				Name: "Mortgage Offer Credential",
				Format: map[string]types.FormatConstraint{
					"vc+sd-jwt": {},
				},
				Constraints: &types.Constraints{
					LimitDisclosure: "required",
					Fields: []types.Field{
						{
							Path:   []string{"$.vct"},
							Filter: &types.Filter{Const: vctValue},
						},
						{
							Path:    []string{"$.bank_name"},
							Purpose: "Identify the offering bank",
						},
						{
							Path:    []string{"$.offer_expiry"},
							Purpose: "Confirm the offer is current",
						},
						{
							Path:    []string{"$.applicant_ref"},
							Purpose: "Match to conveyancing case",
						},
						{
							Path:     []string{"$.max_amount"},
							Optional: true, // we'd like it but don't require it
						},
					},
				},
			},
		},
	}

	authReq, err := conv.NewRequest(ctx, verifier.RequestConfig{Definition: def})
	must(err, "creating authorization request")

	authReqURI, err := verifier.RequestURI(authReq)
	must(err, "building request URI")

	fmt.Println("=== Authorization Request ===")
	fmt.Printf("Nonce:  %s\n", authReq.Nonce)
	fmt.Printf("State:  %s\n", authReq.State)
	fmt.Printf("URI:    openid4vp://?request=<...encoded...>\n\n")
	_ = authReqURI

	// -----------------------------------------------------------------------
	// 3. Aggregator wallet receives the request and builds a response.
	//    In practice the authReq JSON would be delivered via QR or deep link.
	// -----------------------------------------------------------------------

	walletPresenter := &sdJWTPresenter{}

	h := holder.New(
		[]holder.Presenter{walletPresenter},
		holder.WithHTTPClient(srv.Client()),
	)

	reqJSON, _ := json.Marshal(authReq)
	parsedReq, err := h.ParseRequest(ctx, string(reqJSON))
	must(err, "parsing authorization request")

	fmt.Println("=== Wallet parsed request ===")
	fmt.Printf("Purpose: %s\n", parsedReq.PresentationDefinition.Purpose)
	fmt.Printf("Descriptors required: %d\n\n", len(parsedReq.PresentationDefinition.InputDescriptors))

	// Simulate the wallet's credential store — one mortgage offer credential.
	walletCredentials := []holder.StoredCredential{
		{
			ID:     "mortgage-offer-1",
			Format: "vc+sd-jwt",
			// In production this is the real SD-JWT-VC from go-sd-jwt-vc.
			Raw: "eyJhbGciOiJFUzI1NiJ9.mockissuer.sig~disc_bank~disc_expiry~disc_ref~",
			VCT: "https://schema.pyxical.com/MortgageOffer",
			Claims: map[string]any{
				"vct":            "https://schema.pyxical.com/MortgageOffer",
				"bank_name":      "Lloyds Bank plc",
				"offer_expiry":   "2025-10-01",
				"max_amount":     450000.0,
				"currency":       "GBP",
				"applicant_name": "Jane Smith",
				"applicant_ref":  "APP-2025-78291",
			},
		},
	}

	matches, errs := h.SelectCredentials(parsedReq.PresentationDefinition, walletCredentials)
	if len(errs) > 0 {
		log.Fatalf("credential selection failed: %v", errs)
	}

	fmt.Println("=== Wallet credential selection ===")
	for _, m := range matches {
		fmt.Printf("Descriptor %q → credential %q\n", m.DescriptorID, m.Credential.ID)
		fmt.Printf("Suggested disclosures: %v\n\n", m.SuggestedRevealClaims)
	}

	// The user does not consent to reveal max_amount — override the suggestion.
	revealOverride := map[string][]string{
		"mortgage-offer": {"bank_name", "offer_expiry", "applicant_ref"},
	}

	response, err := h.BuildResponse(ctx, parsedReq, matches, revealOverride)
	must(err, "building VP response")

	fmt.Println("=== Wallet VP Token ===")
	fmt.Printf("VP Token (truncated): %s...\n", response.VPToken[:min(60, len(response.VPToken))])
	fmt.Printf("Submission definition_id: %s\n\n", response.PresentationSubmission.DefinitionID)

	// -----------------------------------------------------------------------
	// 4. Wallet submits to the conveyancer's response_uri.
	// -----------------------------------------------------------------------

	if err := h.Submit(ctx, srv.URL+"/vp/response", response); err != nil {
		log.Fatalf("Submit: %v", err)
	}

	// -----------------------------------------------------------------------
	// 5. Conveyancer polls for the result (simulating a browser redirect flow).
	// -----------------------------------------------------------------------

	result, err := conv.PollResult(ctx, authReq.State)
	must(err, "polling result")

	if result == nil {
		log.Fatal("result is still pending — this shouldn't happen in the example")
	}

	fmt.Println("=== Conveyancer Verification Result ===")
	for id, dr := range result.DescriptorResults {
		fmt.Printf("Descriptor: %s\n", id)
		fmt.Printf("  Issuer:     %s\n", dr.Issuer)
		fmt.Printf("  Key bound:  %v\n", dr.KeyBound)
		fmt.Printf("  Disclosed claims:\n")
		printJSON(dr.DisclosedClaims)
	}

	// Confirm max_amount was not disclosed (user withheld it).
	dr := result.DescriptorResults["mortgage-offer"]
	if _, present := dr.DisclosedClaims["max_amount"]; present {
		log.Fatal("max_amount should not have been disclosed")
	}
	fmt.Println("\n✓ max_amount correctly withheld by the wallet")

	// -----------------------------------------------------------------------
	// 6. Demonstrate replay protection.
	// -----------------------------------------------------------------------

	fmt.Println("\n=== Replay attempt ===")
	_, err = conv.ValidateResponse(ctx, response.VPToken, response.PresentationSubmission, authReq.State)
	if err != nil {
		var ve *oid4vp.ValidationError
		if asErr(err, &ve) {
			fmt.Printf("✓ Replay rejected at stage %q: %v\n", ve.Stage, ve.Err)
		}
	}
}

// --- mock implementations ---

// mortgageValidator is a mock CredentialValidator for the example.
// In production, wire in go-sd-jwt-vc's Verifier here.
type mortgageValidator struct {
	issuedClaims map[string]any
}

func (v *mortgageValidator) Format() string { return "vc+sd-jwt" }

func (v *mortgageValidator) Validate(_ context.Context, credential, nonce, audience string) (*verifier.DescriptorResult, error) {
	// A real implementation would call sdjwt.Verifier.Verify(ctx, credential, VerifyOptions{Nonce: nonce})
	// and check the audience against the verifier's clientID.
	_ = nonce
	_ = audience

	// For the example, only return claims that were "disclosed" — simulating
	// the wallet's reveal override (max_amount and currency are absent).
	disclosed := map[string]any{
		"vct":           v.issuedClaims["vct"],
		"bank_name":     v.issuedClaims["bank_name"],
		"offer_expiry":  v.issuedClaims["offer_expiry"],
		"applicant_ref": v.issuedClaims["applicant_ref"],
	}

	return &verifier.DescriptorResult{
		CredentialFormat: "vc+sd-jwt",
		DisclosedClaims:  disclosed,
		AllClaims:        v.issuedClaims,
		Issuer:           "https://lloyds.example",
		KeyBound:         true,
	}, nil
}

// sdJWTPresenter is a mock Presenter for the example.
// In production, wire in go-sd-jwt-vc's Holder.Present here.
type sdJWTPresenter struct{}

func (p *sdJWTPresenter) Format() string { return "vc+sd-jwt" }

func (p *sdJWTPresenter) Present(_ context.Context, raw, nonce, audience string, revealClaims []string) (string, error) {
	// A real implementation would call sdjwt.Holder.Present with the nonce,
	// audience, and revealClaims to produce an SD-JWT + KB-JWT.
	_ = nonce
	_ = audience
	_ = revealClaims
	// Return the raw credential as-is for the example.
	return raw, nil
}

func must(err error, context string) {
	if err != nil {
		log.Fatalf("%s: %v", context, err)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "  ", "  ")
	fmt.Printf("  %s\n", b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func asErr(err error, target **oid4vp.ValidationError) bool {
	e := err
	for e != nil {
		if ve, ok := e.(*oid4vp.ValidationError); ok {
			*target = ve
			return true
		}
		type unwrap interface{ Unwrap() error }
		if u, ok := e.(unwrap); ok {
			e = u.Unwrap()
		} else {
			break
		}
	}
	return false
}
