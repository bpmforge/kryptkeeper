package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// listHub serves a paged list at path ("a" on page 1, the rest on page 2) so
// tests also prove the data sources follow next_cursor.
func listHub(t *testing.T, path string, page1, page2 string) *HubClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			fmt.Fprintf(w, `{"data":[%s],"meta":{"next_cursor":"1"}}`, page1)
			return
		}
		fmt.Fprintf(w, `{"data":[%s],"meta":{"next_cursor":null}}`, page2)
	}))
	t.Cleanup(srv.Close)
	return newTestClient(srv)
}

func readDS(t *testing.T, ds datasource.DataSource, client *HubClient, name string) (datasource.ReadResponse, tfsdk.State) {
	t.Helper()
	ctx := context.Background()
	ds.(datasource.DataSourceWithConfigure).Configure(ctx, datasource.ConfigureRequest{ProviderData: client}, &datasource.ConfigureResponse{})
	var sch datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sch)
	typ := sch.Schema.Type().TerraformType(ctx).(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for k, at := range typ.AttributeTypes {
		vals[k] = tftypes.NewValue(at, nil)
	}
	vals["name"] = tftypes.NewValue(tftypes.String, name)
	cfg := tfsdk.Config{Schema: sch.Schema, Raw: tftypes.NewValue(typ, vals)}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(typ, nil)}}
	ds.Read(ctx, datasource.ReadRequest{Config: cfg}, &resp)
	return resp, resp.State
}

func attr(t *testing.T, s tfsdk.State, name string) string {
	t.Helper()
	var v string
	if d := s.GetAttribute(context.Background(), path.Root(name), &v); d.HasError() {
		t.Fatalf("get %s: %v", name, d)
	}
	return v
}

const (
	caA = `{"id":"ca-a","name":"a","certificate_pem":"PEM-A","certificate":{"subject_dn":"CN=root-a,O=X","public_key_algorithm":"ECDSA","key_size_bits":384}}`
	caB = `{"id":"ca-b","name":"b","certificate_pem":"PEM-B","certificate":{"subject_dn":"O=X, CN=root-b","public_key_algorithm":"RSA","key_size_bits":4096}}`
)

func TestCADataSource_LookupByName(t *testing.T) {
	resp, st := readDS(t, NewCADataSource(), listHub(t, "/api/v1/cas", caA, caB), "b")
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	for k, want := range map[string]string{"id": "ca-b", "common_name": "root-b", "algorithm": "RSA-4096", "certificate_pem": "PEM-B"} {
		if got := attr(t, st, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestCADataSource_AlgorithmFromCertificate(t *testing.T) {
	pemText := rsaCAPEM(t, "from-pem")
	item, _ := json.Marshal(map[string]any{"id": "ca-p", "name": "p", "certificate_pem": pemText,
		"certificate": map[string]any{"subject_dn": "CN=ignored", "public_key_algorithm": "RSA"}})
	resp, st := readDS(t, NewCADataSource(), listHub(t, "/api/v1/cas", string(item), caA), "p")
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if got := attr(t, st, "algorithm"); got != "RSA-2048" {
		t.Errorf("algorithm = %q, want RSA-2048 (the hub reports no RSA size)", got)
	}
	if got := attr(t, st, "common_name"); got != "from-pem" {
		t.Errorf("common_name = %q", got)
	}
}

func TestCADataSource_NotFound(t *testing.T) {
	resp, _ := readDS(t, NewCADataSource(), listHub(t, "/api/v1/cas", caA, caB), "nope")
	if !resp.Diagnostics.HasError() || resp.Diagnostics.Errors()[0].Summary() != "CA not found" {
		t.Fatalf("diagnostics = %v, want summary %q", resp.Diagnostics, "CA not found")
	}
}

func TestCADataSource_Ambiguous(t *testing.T) {
	dup := strings.Replace(caB, `"ca-b"`, `"ca-b2"`, 1)
	resp, _ := readDS(t, NewCADataSource(), listHub(t, "/api/v1/cas", caB, dup), "b")
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), `multiple CAs named "b"`) {
		t.Fatalf("diagnostics = %v, want multiple CAs error", resp.Diagnostics)
	}
}

const (
	tplA = `{"id":"tpl-a","name":"a","display_name":"A","validity_period":"P30D","active":true}`
	tplB = `{"id":"tpl-b","name":"b","display_name":"B","validity_period":"P90D","active":false}`
)

func TestTemplateDataSource_LookupByName(t *testing.T) {
	resp, st := readDS(t, NewTemplateDataSource(), listHub(t, "/api/v1/templates", tplA, tplB), "b")
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	for k, want := range map[string]string{"id": "tpl-b", "display_name": "B", "validity_period": "P90D"} {
		if got := attr(t, st, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	var active bool
	if d := st.GetAttribute(context.Background(), path.Root("active"), &active); d.HasError() || active {
		t.Errorf("active = %v (%v), want false", active, d)
	}
}

func TestTemplateDataSource_NotFound(t *testing.T) {
	resp, _ := readDS(t, NewTemplateDataSource(), listHub(t, "/api/v1/templates", tplA, tplB), "nope")
	if !resp.Diagnostics.HasError() || resp.Diagnostics.Errors()[0].Summary() != "Template not found" {
		t.Fatalf("diagnostics = %v, want summary %q", resp.Diagnostics, "Template not found")
	}
}

func TestProvider_DataSources(t *testing.T) {
	ctx := context.Background()
	p := New("x")()
	dss := p.DataSources(ctx)
	if len(dss) != 2 {
		t.Fatalf("DataSources() = %d, want 2", len(dss))
	}
	var pm fwprovider.MetadataResponse
	p.Metadata(ctx, fwprovider.MetadataRequest{}, &pm)
	var got []string
	for _, f := range dss {
		var m datasource.MetadataResponse
		f().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: pm.TypeName}, &m)
		got = append(got, m.TypeName)
	}
	if strings.Join(got, ",") != "kryptkeeper_ca,kryptkeeper_template" {
		t.Errorf("type names = %v", got)
	}
}

// caChainPEM is what hubWith serves for a CA's /chain export.
var caChainPEM string

// importThenRead drives ImportState then Read the way terraform import does and
// returns the resulting state.
func importThenRead(t *testing.T, r resource.Resource, client *HubClient, id string) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	r.(resource.ResourceWithConfigure).Configure(ctx, resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})
	var sch resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sch)
	typ := sch.Schema.Type().TerraformType(ctx)
	imp := resource.ImportStateResponse{State: tfsdk.State{Schema: sch.Schema, Raw: tftypes.NewValue(typ, nil)}}
	r.(resource.ResourceWithImportState).ImportState(ctx, resource.ImportStateRequest{ID: id}, &imp)
	if imp.Diagnostics.HasError() {
		t.Fatal(imp.Diagnostics)
	}
	if got := attr(t, imp.State, "id"); got != id {
		t.Fatalf("imported id = %q, want %q", got, id)
	}
	rd := resource.ReadResponse{State: imp.State}
	r.Read(ctx, resource.ReadRequest{State: imp.State}, &rd)
	if rd.Diagnostics.HasError() {
		t.Fatal(rd.Diagnostics)
	}
	return rd.State
}

// rsaCAPEM returns a self-signed RSA-2048 CA certificate valid for 365 days.
func rsaCAPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func hubWith(t *testing.T, path, body string) *HubClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == path:
			fmt.Fprint(w, body)
		case strings.HasSuffix(r.URL.Path, "/chain"):
			fmt.Fprint(w, caChainPEM)
		case strings.HasSuffix(r.URL.Path, "/download"):
			fmt.Fprint(w, "PEM")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return newTestClient(srv)
}

// The unit-level stand-in for "post-import plan shows 0 diff": after import +
// Read, every attribute a config sets (and every RequiresReplace one) is filled.
func TestImportState_PostImportNoDiff(t *testing.T) {
	t.Run("ca", func(t *testing.T) {
		// GET /cas/{id} carries no PEM and no RSA key size: both come from the chain export.
		caChainPEM = rsaCAPEM(t, "root")
		c := hubWith(t, "/api/v1/cas/ca-1", `{"data":{"id":"ca-1","name":"root","parent_ca_id":"ca-0","certificate":{"subject_dn":"CN=root,O=X","public_key_algorithm":"RSA"}}}`)
		st := importThenRead(t, NewCAResource(), c, "ca-1")
		var days int64
		if d := st.GetAttribute(context.Background(), path.Root("validity_days"), &days); d.HasError() || days != 365 {
			t.Errorf("validity_days = %d (%v), want 365", days, d)
		}
		for k, want := range map[string]string{"name": "root", "common_name": "root", "algorithm": "RSA-2048", "parent_ca_id": "ca-0", "certificate_pem": strings.TrimSpace(caChainPEM)} {
			if got := attr(t, st, k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
	})
	t.Run("template", func(t *testing.T) {
		c := hubWith(t, "/api/v1/templates/tpl-1", `{"data":{"id":"tpl-1","name":"web","display_name":"Web","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["RSA"],"min_key_size":2048,"active":true}}`)
		st := importThenRead(t, NewTemplateResource(), c, "tpl-1")
		for k, want := range map[string]string{"name": "web", "display_name": "Web", "validity_period": "P30D"} {
			if got := attr(t, st, k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
	})
	t.Run("certificate", func(t *testing.T) {
		c := hubWith(t, "/api/v1/certificates/fp-1", `{"data":{"fingerprint_sha256":"fp-1","common_name":"a.test","valid_until":"2030-01-01T00:00:00Z","ca_id":"ca-1","template_id":"tpl-1"}}`)
		st := importThenRead(t, NewCertificateResource(), c, "fp-1")
		for k, want := range map[string]string{"ca_id": "ca-1", "template_id": "tpl-1", "fingerprint": "fp-1", "common_name": "a.test"} {
			if got := attr(t, st, k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
	})
}

func TestCertificateCSRReplaceRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state types.String
		want  bool
	}{
		{"null (imported)", types.StringNull(), false},
		{"empty", types.StringValue(""), false},
		{"set", types.StringValue("CSR-1"), true},
	} {
		var resp stringplanmodifier.RequiresReplaceIfFuncResponse
		csrRequiresReplace(context.Background(), planmodifier.StringRequest{StateValue: tc.state}, &resp)
		if resp.RequiresReplace != tc.want {
			t.Errorf("%s: replace=%v, want %v", tc.name, resp.RequiresReplace, tc.want)
		}
	}
}
