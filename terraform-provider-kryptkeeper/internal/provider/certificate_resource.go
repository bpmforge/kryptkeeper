package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &CertificateResource{}
var _ resource.ResourceWithImportState = &CertificateResource{}

func NewCertificateResource() resource.Resource { return &CertificateResource{} }

// CertificateResource manages a Kryptkeeper-issued certificate.
type CertificateResource struct {
	client *HubClient
}

// CertificateResourceModel maps the kryptkeeper_certificate schema to Go types.
type CertificateResourceModel struct {
	ID             types.String `tfsdk:"id"`
	CAID           types.String `tfsdk:"ca_id"`
	TemplateID     types.String `tfsdk:"template_id"`
	CSRPEM         types.String `tfsdk:"csr_pem"`
	CertificatePEM types.String `tfsdk:"certificate_pem"`
	ChainPEM       types.String `tfsdk:"chain_pem"`
	Fingerprint    types.String `tfsdk:"fingerprint"`
	CommonName     types.String `tfsdk:"common_name"`
	NotAfter       types.String `tfsdk:"not_after"`
}

func (r *CertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Issues a certificate from a Kryptkeeper CA. Revokes on destroy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The certificate fingerprint (SHA-256).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"ca_id": schema.StringAttribute{
				Required:      true,
				Description:   "The CA to sign with.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"template_id": schema.StringAttribute{
				Required:      true,
				Description:   "The certificate template to apply.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"csr_pem": schema.StringAttribute{
				Required:      true,
				Sensitive:     false,
				Description:   "PEM-encoded Certificate Signing Request (CSR). The hub does not return it, so an imported certificate has none in state and setting it in config afterwards does not force a replacement.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(csrRequiresReplace, "Replace when the CSR changes, unless state holds none (imported certificate).", "Replace when the CSR changes, unless state holds none (imported certificate).")},
			},
			"certificate_pem": schema.StringAttribute{
				Computed:    true,
				Description: "The issued certificate in PEM format.",
			},
			"chain_pem": schema.StringAttribute{
				Computed:    true,
				Description: "The issuing CA chain (issuing CA up to the root) in PEM format.",
			},
			"fingerprint": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 fingerprint of the issued certificate.",
			},
			"common_name": schema.StringAttribute{
				Computed:    true,
				Description: "Subject Common Name of the issued certificate.",
			},
			"not_after": schema.StringAttribute{
				Computed:    true,
				Description: "Certificate expiry timestamp (RFC3339).",
			},
		},
	}
}

func (r *CertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*HubClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *HubClient, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CertificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]string{
		"ca_id":       plan.CAID.ValueString(),
		"template_id": plan.TemplateID.ValueString(),
		"csr_pem":     plan.CSRPEM.ValueString(),
	}

	respBody, err := r.client.Post(ctx, "/api/v1/certificates", body)
	if err != nil {
		resp.Diagnostics.AddError("Error issuing certificate", err.Error())
		return
	}

	var result struct {
		Data struct {
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			CommonName        string `json:"common_name"`
			ValidUntil        string `json:"valid_until"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing certificate response", err.Error())
		return
	}

	plan.ID = types.StringValue(result.Data.FingerprintSHA256)
	plan.Fingerprint = types.StringValue(result.Data.FingerprintSHA256)
	plan.CommonName = types.StringValue(result.Data.CommonName)
	plan.NotAfter = types.StringValue(result.Data.ValidUntil)
	if err := r.loadPEMs(ctx, result.Data.FingerprintSHA256, plan.CAID.ValueString(), &plan); err != nil {
		resp.Diagnostics.AddError("Error fetching issued certificate PEM", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CertificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/certificates/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading certificate", err.Error())
		return
	}
	if respBody == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	var result struct {
		Data struct {
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			CommonName        string `json:"common_name"`
			ValidUntil        string `json:"valid_until"`
			CAID              string `json:"ca_id"`
			TemplateID        string `json:"template_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing certificate response", err.Error())
		return
	}

	// After terraform import ca_id and template_id are null; both force
	// replacement, so take them from the hub.
	if state.CAID.IsNull() && result.Data.CAID != "" {
		state.CAID = types.StringValue(result.Data.CAID)
	}
	if state.TemplateID.IsNull() && result.Data.TemplateID != "" {
		state.TemplateID = types.StringValue(result.Data.TemplateID)
	}
	state.Fingerprint = types.StringValue(result.Data.FingerprintSHA256)
	state.CommonName = types.StringValue(result.Data.CommonName)
	state.NotAfter = types.StringValue(result.Data.ValidUntil)
	if err := r.loadPEMs(ctx, state.ID.ValueString(), state.CAID.ValueString(), &state); err != nil {
		resp.Diagnostics.AddError("Error fetching certificate PEM", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// loadPEMs fills certificate_pem and chain_pem. The hub's issue and get
// responses carry no PEM, so the leaf comes from the download endpoint and
// the chain from the issuing CA's chain endpoint.
func (r *CertificateResource) loadPEMs(ctx context.Context, fingerprint, caID string, m *CertificateResourceModel) error {
	leaf, err := r.client.Get(ctx, "/api/v1/certificates/"+fingerprint+"/download?format=pem")
	if err != nil {
		return err
	}
	chain, err := r.client.Get(ctx, "/api/v1/cas/"+caID+"/chain?format=pem")
	if err != nil {
		return err
	}
	m.CertificatePEM = types.StringValue(string(leaf))
	m.ChainPEM = types.StringValue(string(chain))
	return nil
}

// Update only ever adopts a csr_pem into an imported certificate: the hub does
// not return the CSR, so state has none and the first plan after
// terraform import shows csr_pem going from null to the config value. That is
// recorded in state with no hub call. Every other attribute is RequiresReplace,
// and a change of an existing CSR also replaces (csrRequiresReplace).
func (r *CertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CertificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !state.CSRPEM.IsNull() && state.CSRPEM.ValueString() != "" {
		resp.Diagnostics.AddError("Certificate updates not supported",
			"All certificate attributes are marked RequiresReplace. Terraform will destroy and re-create the certificate.")
		return
	}
	state.CSRPEM = plan.CSRPEM
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CertificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]string{"reason": "terraform destroy"}
	if _, err := r.client.Post(ctx, "/api/v1/certificates/"+state.ID.ValueString()+"/revoke", body); err != nil {
		resp.Diagnostics.AddError("Error revoking certificate", err.Error())
	}
}

// ImportState adopts an existing certificate: the import id is the certificate fingerprint (SHA-256). The Read that
// follows fills every other attribute from the hub.
func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// csrRequiresReplace reports whether a csr_pem change must re-issue the
// certificate. An imported certificate has no CSR in state, so adopting the
// config's value is not a change to the issued object.
func csrRequiresReplace(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.StateValue.IsNull() && req.StateValue.ValueString() != ""
}
