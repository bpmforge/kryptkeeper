package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// newTestClient builds a HubClient pointing at a test server.
func newTestClient(srv *httptest.Server) *HubClient {
	return &HubClient{
		BaseURL:    srv.URL,
		Token:      "test-token",
		HTTPClient: srv.Client(),
	}
}

func TestHubClient_Get_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	body, err := c.Get(context.Background(), "/api/v1/cas/nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for 404, got %v", err)
	}
	if body != nil {
		t.Errorf("expected nil body for 404, got %q", body)
	}
}

func TestHubClient_Get_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "ca-1"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	body, err := c.Get(context.Background(), "/api/v1/cas/ca-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
}

func TestHubClient_Post_Success(t *testing.T) {
	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": "cert-1"}})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	body, err := c.Post(context.Background(), "/api/v1/certificates", map[string]string{
		"ca_id":   "ca-1",
		"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
	if received["ca_id"] != "ca-1" {
		t.Errorf("expected ca_id=ca-1 in POST body, got %q", received["ca_id"])
	}
}

func TestHubClient_Post_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.Post(context.Background(), "/api/v1/certificates", map[string]string{})
	if err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
}

func TestHubClient_Delete_NotFound_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.Delete(context.Background(), "/api/v1/cas/gone"); err != nil {
		t.Errorf("expected nil error for 404 delete, got %v", err)
	}
}

func TestHubClient_Delete_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.Delete(context.Background(), "/api/v1/cas/ca-1"); err == nil {
		t.Error("expected error for 500 delete, got nil")
	}
}

func TestHubClient_SetsBearerToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	c := &HubClient{
		BaseURL:    srv.URL,
		Token:      "my-secret-token",
		HTTPClient: srv.Client(),
	}
	_, _ = c.Get(context.Background(), "/api/v1/cas")
	if authHeader != "Bearer my-secret-token" {
		t.Errorf("expected Bearer token, got %q", authHeader)
	}
}

func TestHubClient_PendingApproval202IsAnError(t *testing.T) {
	cases := map[string]string{
		"data.action_id": `{"data":{"status":"proposed","action_id":"act-7"}}`,
		"approval_id":    `{"status":"pending_approval","approval_id":"act-7"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c := newTestClient(srv)
			ctx := context.Background()
			if _, err := c.Post(ctx, "/x", nil); err == nil || !strings.Contains(err.Error(), "action id act-7") {
				t.Errorf("Post error = %v, want pending action id act-7", err)
			}
			if err := c.Delete(ctx, "/x"); err == nil || !strings.Contains(err.Error(), "action id act-7") {
				t.Errorf("Delete error = %v, want pending action id act-7", err)
			}
		})
	}
}

func TestCAResource_Delete_RevokePendingFailsWithActionID(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{"status":"active"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/cas/ca-1/revoke":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"data":{"action_id":"act-9"}}`))
		case r.Method == http.MethodDelete:
			deleted = true
		}
	}))
	defer srv.Close()

	r := &CAResource{client: newTestClient(srv)}
	ctx := context.Background()
	var sch resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sch)
	state := tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(sch.Schema.Type().TerraformType(ctx), nil)}
	if d := state.SetAttribute(ctx, path.Root("id"), "ca-1"); d.HasError() {
		t.Fatal(d)
	}
	var resp resource.DeleteResponse
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "act-9") {
		t.Fatalf("diagnostics = %v, want an error naming act-9", resp.Diagnostics)
	}
	if deleted {
		t.Error("DELETE was sent although the revoke is only pending")
	}
}
