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

var _ resource.Resource = &CAResource{}

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

	body := map[string]any{
		"name":        plan.Name.ValueString(),
		"common_name": plan.CommonName.ValueString(),
	}
	if !plan.Algorithm.IsNull() && !plan.Algorithm.IsUnknown() {
		body["algorithm"] = plan.Algorithm.ValueString()
	}
	if !plan.KeySize.IsNull() && !plan.KeySize.IsUnknown() {
		body["key_size"] = plan.KeySize.ValueInt64()
	}
	if !plan.ValidityDays.IsNull() && !plan.ValidityDays.IsUnknown() {
		body["validity_days"] = plan.ValidityDays.ValueInt64()
	}
	if !plan.ParentCAID.IsNull() && !plan.ParentCAID.IsUnknown() {
		body["parent_ca_id"] = plan.ParentCAID.ValueString()
	}

	respBody, err := r.client.Post(ctx, "/api/v1/cas", body)
	if err != nil {
		resp.Diagnostics.AddError("Error creating CA", err.Error())
		return
	}

	var result struct {
		Data struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			CommonName     string `json:"common_name"`
			Algorithm      string `json:"algorithm"`
			KeySize        int64  `json:"key_size"`
			ValidityDays   int64  `json:"validity_days"`
			CertificatePEM string `json:"certificate_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing CA response", err.Error())
		return
	}

	plan.ID = types.StringValue(result.Data.ID)
	plan.Algorithm = types.StringValue(result.Data.Algorithm)
	plan.KeySize = types.Int64Value(result.Data.KeySize)
	plan.ValidityDays = types.Int64Value(result.Data.ValidityDays)
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

	var result struct {
		Data struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			CommonName     string `json:"common_name"`
			Algorithm      string `json:"algorithm"`
			KeySize        int64  `json:"key_size"`
			ValidityDays   int64  `json:"validity_days"`
			CertificatePEM string `json:"certificate_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		resp.Diagnostics.AddError("Error parsing CA response", err.Error())
		return
	}

	state.Name = types.StringValue(result.Data.Name)
	state.CommonName = types.StringValue(result.Data.CommonName)
	state.Algorithm = types.StringValue(result.Data.Algorithm)
	state.KeySize = types.Int64Value(result.Data.KeySize)
	state.ValidityDays = types.Int64Value(result.Data.ValidityDays)
	state.CertPEM = types.StringValue(result.Data.CertificatePEM)

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
	if err := r.client.Delete(ctx, "/api/v1/cas/"+state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting CA", err.Error())
	}
}
