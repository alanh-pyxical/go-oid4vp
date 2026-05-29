# go-oid4vp

[![Go Reference](https://pkg.go.dev/badge/github.com/alanh-pyxical/go-oid4vp.svg)](https://pkg.go.dev/github.com/alanh-pyxical/go-oid4vp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An idiomatic Go implementation of [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) with [Presentation Exchange](https://identity.foundation/presentation-exchange/) support.

## Overview

OID4VP defines how a holder presents verifiable credentials to a verifier. This library implements both sides:

| Sub-package | Role | Responsibility |
|---|---|---|
| `verifier` | Conveyancer / Relying Party | Creates authorization requests; validates VP Token responses |
| `holder` | Wallet / Aggregator | Selects credentials; builds and submits VP Token responses |
| `types` | Shared | Protocol types (PresentationDefinition, AuthorizationRequest, etc.) |

## Installation

```sh
go get github.com/alanh-pyxical/go-oid4vp
```

No mandatory external dependencies beyond the standard library.

## Verifier (Relying Party Side)

```go
import (
    "github.com/alanh-pyxical/go-oid4vp/verifier"
    "github.com/alanh-pyxical/go-oid4vp/types"
)

// 1. Implement CredentialValidator to verify presented credentials.
//    Wire in go-sd-jwt-vc's Verifier here.
validator := &mySDJWTValidator{} // implements verifier.CredentialValidator

// 2. Create the verifier.
v, err := verifier.New(
    "https://conveyancer.example",          // clientID
    "https://conveyancer.example/vp/response", // responseURI
    verifier.NewMemorySessionStore(),        // swap for DB-backed in production
    []verifier.CredentialValidator{validator},
    verifier.WithClientMetadata(&types.ClientMetadata{
        Name: "Smith & Jones Conveyancers",
    }),
)

// 3. Mount the handler at your response_uri path.
mux.Handle("POST /vp/response", v.Handler())

// 4. Create a request per verification transaction.
req, err := v.NewRequest(ctx, verifier.RequestConfig{
    Definition: &types.PresentationDefinition{
        ID: "mortgage-check",
        InputDescriptors: []types.InputDescriptor{
            {
                ID: "mortgage-offer",
                Format: map[string]types.FormatConstraint{"vc+sd-jwt": {}},
                Constraints: &types.Constraints{
                    Fields: []types.Field{
                        {Path: []string{"$.vct"}, Filter: &types.Filter{Const: "MortgageOffer"}},
                        {Path: []string{"$.offer_expiry"}},
                    },
                },
            },
        },
    },
})

// 5. Deliver the request to the wallet (QR code, deep link, etc.)
uri, err := verifier.RequestURI(req) // openid4vp://? ...

// 6. After the holder responds, poll for the result.
result, err := v.PollResult(ctx, req.State)
if result != nil {
    claims := result.DescriptorResults["mortgage-offer"].DisclosedClaims
}
```

### Implementing `CredentialValidator`

```go
type CredentialValidator interface {
    Format() string
    Validate(ctx context.Context, credential, nonce, audience string) (*DescriptorResult, error)
}
```

For SD-JWT-VC credentials, implement `Validate` by calling `sdjwt.Verifier.Verify`:

```go
func (v *SDJWTValidator) Validate(ctx context.Context, credential, nonce, audience string) (*verifier.DescriptorResult, error) {
    result, err := v.sdJWTVerifier.Verify(ctx, credential, sdjwt.VerifyOptions{Nonce: nonce})
    if err != nil {
        return nil, err
    }
    return &verifier.DescriptorResult{
        CredentialFormat: "vc+sd-jwt",
        DisclosedClaims:  result.DisclosedClaims,
        AllClaims:        result.IssuerClaims,
        Issuer:           result.Issuer,
        KeyBound:         result.KeyBound,
    }, nil
}
```

## Holder (Wallet Side)

```go
import "github.com/alanh-pyxical/go-oid4vp/holder"

// 1. Implement Presenter to construct presentations.
//    Wire in go-sd-jwt-vc's Holder here.
presenter := &mySDJWTPresenter{} // implements holder.Presenter

// 2. Create the holder.
h := holder.New([]holder.Presenter{presenter})

// 3. Parse the incoming authorization request.
req, err := h.ParseRequest(ctx, authRequestJSON) // or openid4vp:// URI

// 4. Select matching credentials from the wallet.
matches, errs := h.SelectCredentials(req.PresentationDefinition, myWalletCredentials)

// 5. Optionally override which claims to reveal per descriptor.
revealOverride := map[string][]string{
    "mortgage-offer": {"bank_name", "offer_expiry"}, // withhold max_amount
}

// 6. Build the VP Token response.
response, err := h.BuildResponse(ctx, req, matches, revealOverride)

// 7. Submit to the verifier.
err = h.Submit(ctx, req.ResponseURI, response)
```

### Implementing `Presenter`

```go
type Presenter interface {
    Format() string
    Present(ctx context.Context, raw, nonce, audience string, revealClaims []string) (string, error)
}
```

For SD-JWT-VC credentials, implement `Present` by calling `sdjwt.Holder.Present`:

```go
func (p *SDJWTPresenter) Present(ctx context.Context, raw, nonce, audience string, reveal []string) (string, error) {
    tok, err := sdjwt.Parse(raw)
    if err != nil {
        return "", err
    }
    presented, err := p.sdJWTHolder.Present(ctx, tok, sdjwt.PresentOptions{
        RevealClaims: reveal,
        KeyBinding:   true,
        Nonce:        nonce,
        Audience:     audience,
    })
    if err != nil {
        return "", err
    }
    return presented.String(), nil
}
```

## Presentation Definition Builder

Use the `types` package directly to build definitions; the struct API is clear enough that a separate builder is not needed for most cases. For complex combinatorial rules (OR groups), set `SubmissionRequirements` on the `PresentationDefinition`.

## Session Storage

The library ships with `verifier.MemorySessionStore` for tests. For production, implement `SessionStore` against your database:

```go
type SessionStore interface {
    Save(ctx context.Context, session *VerificationSession) error
    Get(ctx context.Context, state string) (*VerificationSession, error)
    Complete(ctx context.Context, state string, result *VerificationResult) error
}
```

## Error Handling

```go
result, err := v.ValidateResponse(ctx, vpToken, submission, state)
if err != nil {
    var ve *oid4vp.ValidationError
    if errors.As(err, &ve) {
        log.Printf("failed at stage %s (descriptor %q): %v", ve.Stage, ve.DescriptorID, ve.Err)
    }
    if errors.Is(err, oid4vp.ErrSubmissionMismatch) { ... }
    if errors.Is(err, oid4vp.ErrNoMatchingCredential) { ... }
}
```

## Protocol Support

| Feature | Status |
|---|---|
| `direct_post` response mode | ✅ |
| Inline `presentation_definition` | ✅ |
| `presentation_definition_uri` (remote fetch) | ✅ |
| `openid4vp://` URI encoding | ✅ |
| Single-credential VP Token | ✅ |
| Multi-credential VP Token (JSON array) | ✅ |
| Field constraint validation (`const`, `enum`, `minimum`, `maximum`) | ✅ |
| `limit_disclosure` hint | ✅ (passed to Presenter) |
| `submission_requirements` (OR groups) | Planned |
| `request_uri` (JWT-secured request) | Planned |

## Related Libraries

- [`go-sd-jwt-vc`](https://github.com/alanh-pyxical/go-sd-jwt-vc) — SD-JWT-VC issuance and verification
- [`go-oid4vci`](https://github.com/alanh-pyxical/go-oid4vci) — OpenID for Verifiable Credential Issuance

## License

MIT — see [LICENSE](LICENSE).
