package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &CertificateResource{}

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
				Description:   "PEM-encoded Certificate Signing Request (CSR).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"certificate_pem": schema.StringAttribute{
				Computed:    true,
				Description: "The issued certificate in PEM format.",
			},
			"chain_pem": schema.StringAttribute{
				Computed:    true,
				Description: "The full certificate chain (leaf + intermediates) in PEM format.",
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
			CertificatePEM    string `json:"certificate_pem"`
			ChainPEM          string `json:"chain_pem"`
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
	plan.CertificatePEM = types.StringValue(result.Data.CertificatePEM)
	plan.ChainPEM = types.StringValue(result.Data.ChainPEM)
	plan.NotAfter = types.StringValue(result.Data.ValidUntil)

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
			CertificatePEM    string `json:"certificate_pem"`
			ChainPEM          string `json:"chain_pem"`
			ValidUntil        string `json:"valid_until"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing certificate response", err.Error())
		return
	}

	state.Fingerprint = types.StringValue(result.Data.FingerprintSHA256)
	state.CommonName = types.StringValue(result.Data.CommonName)
	state.CertificatePEM = types.StringValue(result.Data.CertificatePEM)
	state.ChainPEM = types.StringValue(result.Data.ChainPEM)
	state.NotAfter = types.StringValue(result.Data.ValidUntil)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is not supported — certificates are immutable; re-issue with RequiresReplace.
func (r *CertificateResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Certificate updates not supported",
		"All certificate attributes are marked RequiresReplace. Terraform will destroy and re-create the certificate.")
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
