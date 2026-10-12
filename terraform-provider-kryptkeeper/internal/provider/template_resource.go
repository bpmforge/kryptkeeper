package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &TemplateResource{}

func NewTemplateResource() resource.Resource { return &TemplateResource{} }

// TemplateResource manages a Kryptkeeper certificate template.
type TemplateResource struct {
	client *HubClient
}

// TemplateResourceModel maps the kryptkeeper_template schema to Go types.
type TemplateResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	DisplayName    types.String `tfsdk:"display_name"`
	ValidityPeriod types.String `tfsdk:"validity_period"`
	KeyUsage       types.List   `tfsdk:"key_usage"`
	ExtKeyUsage    types.List   `tfsdk:"extended_key_usage"`
	Algorithms     types.List   `tfsdk:"allowed_algorithms"`
	AutoEnroll     types.Bool   `tfsdk:"auto_enroll"`
	Active         types.Bool   `tfsdk:"active"`
}

func (r *TemplateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_template"
}

func (r *TemplateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Kryptkeeper certificate template defining allowed algorithms, validity, and key usage.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Template unique identifier.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Machine-readable template name (slug).",
			},
			"display_name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable display name.",
			},
			"validity_period": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "ISO 8601 duration, e.g. P90D for 90 days.",
			},
			"key_usage": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "X.509 key usage flags: digitalSignature, keyEncipherment, etc.",
			},
			"extended_key_usage": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Extended key usage OIDs: serverAuth, clientAuth, etc.",
			},
			"allowed_algorithms": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Allowed key algorithms. Empty means any.",
			},
			"auto_enroll": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Enable auto-enrollment for this template.",
			},
			"active": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the template is active and can be used for issuance.",
			},
		},
	}
}

func (r *TemplateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TemplateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TemplateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := templateModelToMap(ctx, plan)
	respBody, err := r.client.Post(ctx, "/api/v1/templates", body)
	if err != nil {
		resp.Diagnostics.AddError("Error creating template", err.Error())
		return
	}

	if err := applyTemplateResponse(ctx, respBody, &plan); err != nil {
		resp.Diagnostics.AddError("Error parsing template response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TemplateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TemplateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	respBody, err := r.client.Get(ctx, "/api/v1/templates/"+state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading template", err.Error())
		return
	}
	if respBody == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if err := applyTemplateResponse(ctx, respBody, &state); err != nil {
		resp.Diagnostics.AddError("Error parsing template response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TemplateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TemplateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := templateModelToMap(ctx, plan)
	respBody, err := r.client.Put(ctx, "/api/v1/templates/"+plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Error updating template", err.Error())
		return
	}
	if err := applyTemplateResponse(ctx, respBody, &plan); err != nil {
		resp.Diagnostics.AddError("Error parsing template response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TemplateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TemplateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/api/v1/templates/"+state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting template", err.Error())
	}
}

func templateModelToMap(ctx context.Context, m TemplateResourceModel) map[string]any {
	body := map[string]any{
		"name":         m.Name.ValueString(),
		"display_name": m.DisplayName.ValueString(),
		"auto_enroll":  m.AutoEnroll.ValueBool(),
		"active":       m.Active.ValueBool(),
	}
	if !m.ValidityPeriod.IsNull() && !m.ValidityPeriod.IsUnknown() {
		body["validity_period"] = m.ValidityPeriod.ValueString()
	}
	if !m.KeyUsage.IsNull() && !m.KeyUsage.IsUnknown() {
		var ku []string
		_ = m.KeyUsage.ElementsAs(ctx, &ku, false)
		body["key_usage"] = ku
	}
	if !m.ExtKeyUsage.IsNull() && !m.ExtKeyUsage.IsUnknown() {
		var eku []string
		_ = m.ExtKeyUsage.ElementsAs(ctx, &eku, false)
		body["extended_key_usage"] = eku
	}
	if !m.Algorithms.IsNull() && !m.Algorithms.IsUnknown() {
		var algs []string
		_ = m.Algorithms.ElementsAs(ctx, &algs, false)
		body["allowed_algorithms"] = algs
	}
	return body
}

func applyTemplateResponse(ctx context.Context, respBody []byte, m *TemplateResourceModel) error {
	var result struct {
		Data struct {
			ID             string   `json:"id"`
			Name           string   `json:"name"`
			DisplayName    string   `json:"display_name"`
			ValidityPeriod string   `json:"validity_period"`
			KeyUsage       []string `json:"key_usage"`
			ExtKeyUsage    []string `json:"extended_key_usage"`
			Algorithms     []string `json:"allowed_algorithms"`
			AutoEnroll     bool     `json:"auto_enroll"`
			Active         bool     `json:"active"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return err
	}
	d := result.Data
	m.ID = types.StringValue(d.ID)
	m.Name = types.StringValue(d.Name)
	m.DisplayName = types.StringValue(d.DisplayName)
	m.ValidityPeriod = types.StringValue(d.ValidityPeriod)
	m.AutoEnroll = types.BoolValue(d.AutoEnroll)
	m.Active = types.BoolValue(d.Active)

	ku, diags := types.ListValueFrom(ctx, types.StringType, d.KeyUsage)
	if diags.HasError() {
		return fmt.Errorf("key_usage list conversion failed")
	}
	m.KeyUsage = ku

	eku, diags := types.ListValueFrom(ctx, types.StringType, d.ExtKeyUsage)
	if diags.HasError() {
		return fmt.Errorf("extended_key_usage list conversion failed")
	}
	m.ExtKeyUsage = eku

	algs, diags := types.ListValueFrom(ctx, types.StringType, d.Algorithms)
	if diags.HasError() {
		return fmt.Errorf("allowed_algorithms list conversion failed")
	}
	m.Algorithms = algs
	return nil
}
