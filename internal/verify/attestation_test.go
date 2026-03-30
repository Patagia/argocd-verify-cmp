package verify

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildDSSEPayload(t *testing.T, predicateType string, predicate map[string]any) []byte {
	t.Helper()
	predicateJSON, err := json.Marshal(predicate)
	if err != nil {
		t.Fatalf("marshaling predicate: %v", err)
	}
	envelope := map[string]string{
		"payloadType": predicateType,
		"payload":     base64.StdEncoding.EncodeToString(predicateJSON),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	return data
}

const testPredicateType = "https://example.com/blessing/v1"

func TestMatchesAttestation_PredicateTypeMatch(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{})
	if !matchesAttestation(payload, testPredicateType, nil) {
		t.Error("expected match for correct predicateType")
	}
}

func TestMatchesAttestation_PredicateTypeMismatch(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{})
	if matchesAttestation(payload, "https://example.com/other", nil) {
		t.Error("expected no match for wrong predicateType")
	}
}

func TestMatchesAttestation_NoClaims(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{
		"approved": true,
		"extra":    "field",
	})
	if !matchesAttestation(payload, testPredicateType, nil) {
		t.Error("expected match when no claims required")
	}
}

func TestMatchesAttestation_ClaimsMatch(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{
		"approved": true,
		"reviewer": "alice@example.com",
	})
	claims := map[string]string{"approved": "true", "reviewer": "alice@example.com"}
	if !matchesAttestation(payload, testPredicateType, claims) {
		t.Error("expected match with correct claims")
	}
}

func TestMatchesAttestation_ClaimsPartialMatch(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{
		"approved": true,
	})
	claims := map[string]string{"approved": "true", "reviewer": "alice@example.com"}
	if matchesAttestation(payload, testPredicateType, claims) {
		t.Error("expected no match when a required claim is absent from predicate")
	}
}

func TestMatchesAttestation_ClaimValueMismatch(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{
		"approved": false,
	})
	claims := map[string]string{"approved": "true"}
	if matchesAttestation(payload, testPredicateType, claims) {
		t.Error("expected no match for mismatched claim value")
	}
}

func TestMatchesAttestation_NumberClaim(t *testing.T) {
	payload := buildDSSEPayload(t, testPredicateType, map[string]any{
		"score": 42,
	})
	claims := map[string]string{"score": "42"}
	if !matchesAttestation(payload, testPredicateType, claims) {
		t.Error("expected match for numeric claim via fmt.Sprint")
	}
}

func TestMatchesAttestation_InvalidJSON(t *testing.T) {
	if matchesAttestation([]byte("not json"), testPredicateType, nil) {
		t.Error("expected no match for invalid payload")
	}
}

func TestMatchesAttestation_InvalidBase64Payload(t *testing.T) {
	data, _ := json.Marshal(map[string]string{
		"payloadType": testPredicateType,
		"payload":     "!!!not-base64!!!",
	})
	if matchesAttestation(data, testPredicateType, map[string]string{"approved": "true"}) {
		t.Error("expected no match for invalid base64 in payload")
	}
}
