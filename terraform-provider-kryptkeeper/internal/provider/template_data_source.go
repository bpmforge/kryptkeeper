package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &TemplateDataSource{}

// NewTemplateDataSource returns a data source factory for kryptkeeper_template.
func NewTemplateDataSource() datasource.DataSource { return &TemplateDataSource{} }

// TemplateDataSource looks up an existing certificate template by its exact name.
type TemplateDataSource struct {
	client *HubClient
}

// TemplateDataSourceModel maps the kryptkeeper_template data source schema to Go types.
type TemplateDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	DisplayName    types.String `tfsdk:"display_name"`
	ValidityPeriod types.String `tfsdk:"validity_period"`
	Active         types.Bool   `tfsdk:"active"`
}

func (d *TemplateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_template"
}

func (d *TemplateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up an existing Kryptkeeper certificate template by name.",
		Attributes: map[string]schema.Attribute{
			"name":            schema.StringAttribute{Required: true, Description: "Exact (case-sensitive) template name."},
			"id":              schema.StringAttribute{Computed: true, Description: "Template unique identifier."},
			"display_name":    schema.StringAttribute{Computed: true, Description: "Human-readable display name."},
			"validity_period": schema.StringAttribute{Computed: true, Description: "ISO 8601 duration, e.g. P90D."},
			"active":          schema.BoolAttribute{Computed: true, Description: "Whether the template can be used for issuance."},
		},
	}
}

func (d *TemplateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *TemplateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg TemplateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := cfg.Name.ValueString()
	matches, err := listByName(ctx, d.client, "/api/v1/templates", name)
	if err != nil {
		resp.Diagnostics.AddError("Error listing templates", err.Error())
		return
	}
	switch len(matches) {
	case 0:
		resp.Diagnostics.AddError("Template not found", fmt.Sprintf("no template named %q", name))
		return
	case 1:
	default:
		resp.Diagnostics.AddError("Multiple templates found", fmt.Sprintf("multiple templates named %q", name))
		return
	}
	var t struct {
		ID             string `json:"id"`
		DisplayName    string `json:"display_name"`
		ValidityPeriod string `json:"validity_period"`
		Active         bool   `json:"active"`
	}
	if err := json.Unmarshal(matches[0], &t); err != nil {
		resp.Diagnostics.AddError("Error parsing template response", err.Error())
		return
	}
	cfg.ID = types.StringValue(t.ID)
	cfg.DisplayName = types.StringValue(t.DisplayName)
	cfg.ValidityPeriod = types.StringValue(t.ValidityPeriod)
	cfg.Active = types.BoolValue(t.Active)
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
