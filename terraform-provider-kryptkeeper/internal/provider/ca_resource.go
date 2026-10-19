package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &CAResource{}
var _ resource.ResourceWithImportState = &CAResource{}

// NewCAResource returns a resource factory for kryptkeeper_ca.
func NewCAResource() resource.Resource { return &CAResource{} }

// CAResource manages a Kryptkeeper Certificate Authority.
type CAResource struct {
	client *HubClient
}

// CAResourceModel maps the kryptkeeper_ca schema to Go types.
type CAResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	CommonName   types.String `tfsdk:"common_name"`
	Algorithm    types.String `tfsdk:"algorithm"`
	KeySize      types.Int64  `tfsdk:"key_size"`
	ValidityDays types.Int64  `tfsdk:"validity_days"`
	ParentCAID   types.String `tfsdk:"parent_ca_id"`
	CertPEM      types.String `tfsdk:"certificate_pem"`
}

func (r *CAResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca"
}

func (r *CAResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Kryptkeeper Certificate Authority (root or intermediate).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The CA's unique identifier.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable name for the CA.",
			},
			"common_name": schema.StringAttribute{
				Required:    true,
				Description: "The CA certificate Subject Common Name.",
			},
			"algorithm": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Key algorithm: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, ML-DSA-44, ML-DSA-65, ML-DSA-87. Defaults to ECDSA-P384.",
			},
			"key_size": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Key size in bits (for RSA only).",
			},
			"validity_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "CA certificate validity in days (default: 3650).",
			},
			"parent_ca_id": schema.StringAttribute{
				Optional:      true,
				Description:   "ID of the parent CA for intermediate CAs. Omit for root CAs.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"certificate_pem": schema.StringAttribute{
				Computed:    true,
				Sensitive:   false,
				Description: "The issued CA certificate in PEM format.",
			},
		},
	}
}

func (r *CAResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *CAResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CAResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Hub contract (CACreateRequest): subject_cn, type, algorithm, validity.
	// The algorithm names the key size (e.g. RSA-2048), so key_size is not sent.
	caType := "root"
	body := map[string]any{
		"name":       plan.Name.ValueString(),
		"subject_cn": plan.CommonName.ValueString(),
		"algorithm":  "ECDSA-P384",
		"validity":   "3650d",
	}
	if !plan.Algorithm.IsNull() && !plan.Algorithm.IsUnknown() {
		body["algorithm"] = plan.Algorithm.ValueString()
	}
	if !plan.ValidityDays.IsNull() && !plan.ValidityDays.IsUnknown() {
		body["validity"] = fmt.Sprintf("%dd", plan.ValidityDays.ValueInt64())
	}
	if !plan.ParentCAID.IsNull() && !plan.ParentCAID.IsUnknown() {
		body["parent_ca_id"] = plan.ParentCAID.ValueString()
		caType = "intermediate"
	}
	body["type"] = caType

	respBody, err := r.client.Post(ctx, "/api/v1/cas", body)
	if err != nil {
		resp.Diagnostics.AddError("Error creating CA", err.Error())
		return
	}

	var result struct {
		Data struct {
			ID             string `json:"id"`
			CertificatePEM string `json:"certificate_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing CA response", err.Error())
		return
	}

	// The hub does not echo key_size or validity_days; keep what was planned
	// and resolve unknowns to the values sent.
	plan.ID = types.StringValue(result.Data.ID)
	if plan.Algorithm.IsNull() || plan.Algorithm.IsUnknown() {
		plan.Algorithm = types.StringValue(body["algorithm"].(string))
	}
	if plan.KeySize.IsNull() || plan.KeySize.IsUnknown() {
		plan.KeySize = types.Int64Value(0)
	}
	if plan.ValidityDays.IsNull() || plan.ValidityDays.IsUnknown() {
		plan.ValidityDays = types.Int64Value(3650)
	}
	plan.CertPEM = types.StringValue(result.Data.CertificatePEM)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CAResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CAResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/cas/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading CA", err.Error())
		return
	}
	if respBody == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// GET /cas/{id} carries no certificate_pem, key_size or validity_days, so
	// state keeps those values; Read confirms the CA still exists, tracks its
	// name and fills what an imported CA lacks.
	var result struct {
		Data struct {
			Name           string  `json:"name"`
			ParentCAID     *string `json:"parent_ca_id"`
			CertificatePEM string  `json:"certificate_pem"`
			Certificate    *struct {
				SubjectDN    string `json:"subject_dn"`
				PublicKeyAlg string `json:"public_key_algorithm"`
				KeySizeBits  int    `json:"key_size_bits"`
			} `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing CA response", err.Error())
		return
	}
	if result.Data.Name != "" {
		state.Name = types.StringValue(result.Data.Name)
	}
	// After terraform import these are null; fill them from the hub so the
	// config's values do not show a diff (or, for parent_ca_id, a replacement).
	if p := result.Data.ParentCAID; p != nil && *p != "" && state.ParentCAID.IsNull() {
		state.ParentCAID = types.StringValue(*p)
	}
	if state.CertPEM.IsNull() {
		if pemText := r.caCertPEM(ctx, state.ID.ValueString(), result.Data.CertificatePEM); pemText != "" {
			state.CertPEM = types.StringValue(pemText)
		}
	}
	if info, ok := parseCACert(state.CertPEM.ValueString()); ok {
		if state.CommonName.IsNull() {
			state.CommonName = types.StringValue(info.commonName)
		}
		if state.Algorithm.IsNull() {
			state.Algorithm = types.StringValue(info.algorithm)
		}
		if state.ValidityDays.IsNull() {
			state.ValidityDays = types.Int64Value(info.validityDays)
		}
	}
	if state.KeySize.IsNull() {
		state.KeySize = types.Int64Value(0) // the hub does not echo it; Create also records 0
	}
	if c := result.Data.Certificate; c != nil {
		if state.CommonName.IsNull() {
			if cn := commonNameFromDN(c.SubjectDN); cn != "" {
				state.CommonName = types.StringValue(cn)
			}
		}
		if state.Algorithm.IsNull() && c.PublicKeyAlg != "" {
			state.Algorithm = types.StringValue(caAlgorithmName(c.PublicKeyAlg, c.KeySizeBits))
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CAResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CAResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"common_name": plan.CommonName.ValueString(),
	}
	_, err := r.client.Put(ctx, "/api/v1/cas/"+plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Error updating CA", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CAResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CAResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The hub only deletes revoked CAs. Revocation is dual-controlled: the
	// first call answers 202 with a pending action id, which surfaces here as
	// an error so the destroy stops until a second admin approves it. No reason
	// is sent: the hub accepts only cACompromise for a CA and defaults to it.
	if !r.isRevoked(ctx, state.ID.ValueString()) {
		if _, err := r.client.Post(ctx, "/api/v1/cas/"+state.ID.ValueString()+"/revoke", map[string]string{}); err != nil {
			resp.Diagnostics.AddError("Error revoking CA", err.Error())
			return
		}
	}
	if err := r.client.Delete(ctx, "/api/v1/cas/"+state.ID.ValueString()); err != nil {
		detail := err.Error()
		// The hub keeps a revoked CA's record: DELETE answers 409 because the
		// CA's own certificate row still references it. A revoked CA can issue
		// nothing, so drop it from state and say what happened.
		if strings.Contains(detail, ": 409:") && r.isRevoked(ctx, state.ID.ValueString()) {
			resp.Diagnostics.AddWarning("CA revoked, not deleted",
				"The CA is revoked and cannot issue certificates, but the hub keeps revoked CA records, so it was removed from Terraform state only. "+detail)
			return
		}
		if strings.Contains(detail, ": 409:") || strings.Contains(detail, ": 422:") {
			detail = "CA must be revoked (dual control) before it can be deleted: POST /api/v1/cas/{id}/revoke then have a second admin approve it. Hub said: " + detail
		}
		resp.Diagnostics.AddError("Error deleting CA", detail)
	}
}

// isRevoked reports whether the hub shows the CA with status revoked.
func (r *CAResource) isRevoked(ctx context.Context, id string) bool {
	body, err := r.client.Get(ctx, "/api/v1/cas/"+id)
	if err != nil || body == nil {
		return false
	}
	var v struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	return json.Unmarshal(body, &v) == nil && v.Data.Status == "revoked"
}

// ImportState adopts an existing CA: the import id is the CA id. The Read that
// follows fills every other attribute from the hub.
func (r *CAResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// caCertPEM returns the CA's own certificate: the PEM from GET /cas/{id} when
// it carries one, else the first block of the CA's chain export.
func (r *CAResource) caCertPEM(ctx context.Context, id, fromGet string) string {
	if strings.TrimSpace(fromGet) != "" {
		return strings.TrimSpace(fromGet)
	}
	chain, err := r.client.Get(ctx, "/api/v1/cas/"+id+"/chain?format=pem")
	if err != nil || chain == nil {
		return ""
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		return ""
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(block)))
}
