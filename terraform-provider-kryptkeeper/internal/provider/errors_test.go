package provider

import (
	"strings"
	"testing"
)

func TestFormatAPIError_JSON(t *testing.T) {
	body := []byte(`{"error":"policy_violation","message":"policy violation [key_size]: key size 1024 bits is below template minimum 2048"}`)
	err := formatAPIError("POST", "/api/v1/certificates", 422, body)
	got := err.Error()
	for _, want := range []string{"POST /api/v1/certificates: 422:", "policy_violation", "[key_size]", "minimum 2048"} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q missing %q", got, want)
		}
	}
}

func TestFormatAPIError_NonJSON(t *testing.T) {
	err := formatAPIError("GET", "/api/v1/cas/x", 500, []byte("  bad gateway\n"))
	if want := "GET /api/v1/cas/x: 500: bad gateway"; err.Error() != want {
		t.Errorf("got %q want %q", err.Error(), want)
	}
}
