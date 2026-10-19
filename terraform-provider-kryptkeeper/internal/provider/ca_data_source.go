package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/url"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &CADataSource{}

// NewCADataSource returns a data source factory for kryptkeeper_ca.
func NewCADataSource() datasource.DataSource { return &CADataSource{} }

// CADataSource looks up an existing CA by its exact name.
type CADataSource struct {
	client *HubClient
}

// CADataSourceModel maps the kryptkeeper_ca data source schema to Go types.
type CADataSourceModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	CommonName types.String `tfsdk:"common_name"`
	Algorithm  types.String `tfsdk:"algorithm"`
	CertPEM    types.String `tfsdk:"certificate_pem"`
}

func (d *CADataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca"
}

func (d *CADataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up an existing Kryptkeeper Certificate Authority by name.",
		Attributes: map[string]schema.Attribute{
			"name":            schema.StringAttribute{Required: true, Description: "Exact (case-sensitive) CA name."},
			"id":              schema.StringAttribute{Computed: true, Description: "The CA's unique identifier."},
			"common_name":     schema.StringAttribute{Computed: true, Description: "Subject Common Name of the CA certificate."},
			"algorithm":       schema.StringAttribute{Computed: true, Description: "Key algorithm (for example RSA-2048, ECDSA-P384)."},
			"certificate_pem": schema.StringAttribute{Computed: true, Description: "The CA certificate in PEM format (public)."},
		},
	}
}

func (d *CADataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*HubClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *HubClient, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *CADataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg CADataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := cfg.Name.ValueString()
	matches, err := listByName(ctx, d.client, "/api/v1/cas", name)
	if err != nil {
		resp.Diagnostics.AddError("Error listing CAs", err.Error())
		return
	}
	switch len(matches) {
	case 0:
		resp.Diagnostics.AddError("CA not found", fmt.Sprintf("no CA named %q", name))
		return
	case 1:
	default:
		resp.Diagnostics.AddError("Multiple CAs found", fmt.Sprintf("multiple CAs named %q", name))
		return
	}
	var ca struct {
		ID             string `json:"id"`
		CertificatePEM string `json:"certificate_pem"`
		Certificate    *struct {
			SubjectDN    string `json:"subject_dn"`
			PublicKeyAlg string `json:"public_key_algorithm"`
			KeySizeBits  int    `json:"key_size_bits"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(matches[0], &ca); err != nil {
		resp.Diagnostics.AddError("Error parsing CA response", err.Error())
		return
	}
	cfg.ID = types.StringValue(ca.ID)
	cfg.CertPEM = types.StringValue(ca.CertificatePEM)
	cfg.CommonName = types.StringValue("")
	cfg.Algorithm = types.StringValue("")
	if ca.Certificate != nil {
		cfg.CommonName = types.StringValue(commonNameFromDN(ca.Certificate.SubjectDN))
		cfg.Algorithm = types.StringValue(caAlgorithmName(ca.Certificate.PublicKeyAlg, ca.Certificate.KeySizeBits))
	}
	// The hub reports no RSA key size, so prefer what the certificate itself says.
	if info, ok := parseCACert(ca.CertificatePEM); ok {
		cfg.CommonName = types.StringValue(info.commonName)
		cfg.Algorithm = types.StringValue(info.algorithm)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

var cnRE = regexp.MustCompile(`(?:^|,)\s*CN=([^,]+)`)

// commonNameFromDN extracts the CN from an RFC 2253 style subject DN.
func commonNameFromDN(dn string) string {
	if m := cnRE.FindStringSubmatch(dn); m != nil {
		return m[1]
	}
	return ""
}

// caAlgorithmName maps the hub's reported key algorithm and size to the
// names the kryptkeeper_ca resource accepts (RSA-2048, ECDSA-P384). Anything
// else (ML-DSA-65, unknown) is passed through unchanged.
func caAlgorithmName(alg string, bits int) string {
	switch {
	case alg == "RSA" && (bits == 2048 || bits == 4096):
		return fmt.Sprintf("RSA-%d", bits)
	case alg == "ECDSA" && (bits == 256 || bits == 384):
		return fmt.Sprintf("ECDSA-P%d", bits)
	}
	return alg
}

// listByName pages through a hub list endpoint ({"data":[...],"meta":
// {"next_cursor"}}) and returns every item whose "name" equals name exactly.
func listByName(ctx context.Context, c *HubClient, path, name string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	cursor := ""
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		body, err := c.Get(ctx, path+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var page struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				NextCursor *string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, item := range page.Data {
			var n struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(item, &n) == nil && n.Name == name {
				out = append(out, item)
			}
		}
		if page.Meta.NextCursor == nil || *page.Meta.NextCursor == "" || *page.Meta.NextCursor == cursor {
			return out, nil
		}
		cursor = *page.Meta.NextCursor
	}
}

// caCertInfo is what a CA certificate itself says about the CA.
type caCertInfo struct {
	commonName   string
	algorithm    string // RSA-2048, ECDSA-P384, ... as the kryptkeeper_ca resource spells it
	validityDays int64
}

// parseCACert reads the first CERTIFICATE block of pemText. The hub's CA JSON
// carries no RSA key size, so the resource and data source take the algorithm,
// common name and validity from the certificate.
func parseCACert(pemText string) (caCertInfo, bool) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return caCertInfo{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return caCertInfo{}, false
	}
	info := caCertInfo{
		commonName:   cert.Subject.CommonName,
		validityDays: int64(math.Round(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)),
		algorithm:    cert.PublicKeyAlgorithm.String(),
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.algorithm = fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		info.algorithm = fmt.Sprintf("ECDSA-P%d", k.Curve.Params().BitSize)
	}
	return info, true
}
