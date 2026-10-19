// Package provider implements the Terraform provider for Kryptkeeper.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure KryptKeeperProvider satisfies the provider.Provider interface.
var _ provider.Provider = &KryptKeeperProvider{}
var _ provider.ProviderWithFunctions = &KryptKeeperProvider{}

// KryptKeeperProvider is the root Terraform provider.
type KryptKeeperProvider struct {
	version string
}

// KryptKeeperProviderModel maps the provider schema to Go types.
type KryptKeeperProviderModel struct {
	HubURL types.String `tfsdk:"hub_url"`
	Token  types.String `tfsdk:"token"`
}

// New returns a provider factory for the given version string.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KryptKeeperProvider{version: version}
	}
}

func (p *KryptKeeperProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kryptkeeper"
	resp.Version = p.version
}

func (p *KryptKeeperProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with the Kryptkeeper PKI Hub to manage certificate authorities, certificates, and templates.",
		Attributes: map[string]schema.Attribute{
			"hub_url": schema.StringAttribute{
				Description: "Kryptkeeper Hub base URL (e.g. https://kryptkeeper.example.com). May also be set via KRYPTKEEPER_HUB_URL environment variable.",
				Required:    true,
			},
			"token": schema.StringAttribute{
				Description: "Kryptkeeper API bearer token. May also be set via KRYPTKEEPER_TOKEN environment variable.",
				Required:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *KryptKeeperProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config KryptKeeperProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hubURL := config.HubURL.ValueString()
	token := config.Token.ValueString()

	if hubURL == "" {
		resp.Diagnostics.AddError("Missing hub_url", "The hub_url provider attribute is required.")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing token", "The token provider attribute is required.")
		return
	}

	client := &HubClient{
		BaseURL:    strings.TrimRight(hubURL, "/"),
		Token:      token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *KryptKeeperProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCAResource,
		NewCertificateResource,
		NewTemplateResource,
	}
}

func (p *KryptKeeperProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCADataSource,
		NewTemplateDataSource,
	}
}

func (p *KryptKeeperProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}

// HubClient is a minimal HTTP client for the Kryptkeeper Hub API.
type HubClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func (c *HubClient) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

func (c *HubClient) Get(ctx context.Context, path string) ([]byte, error) {
	body, status, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, formatAPIError("GET", path, status, body)
	}
	return body, nil
}

func (c *HubClient) Post(ctx context.Context, path string, body any) ([]byte, error) {
	respBody, status, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		return nil, pendingApprovalError("POST", path, respBody)
	}
	if status < 200 || status >= 300 {
		return nil, formatAPIError("POST", path, status, respBody)
	}
	return respBody, nil
}

func (c *HubClient) Put(ctx context.Context, path string, body any) ([]byte, error) {
	respBody, status, err := c.do(ctx, http.MethodPut, path, body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		return nil, pendingApprovalError("PUT", path, respBody)
	}
	if status < 200 || status >= 300 {
		return nil, formatAPIError("PUT", path, status, respBody)
	}
	return respBody, nil
}

func (c *HubClient) Patch(ctx context.Context, path string, body any) ([]byte, error) {
	respBody, status, err := c.do(ctx, http.MethodPatch, path, body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		return nil, pendingApprovalError("PATCH", path, respBody)
	}
	if status < 200 || status >= 300 {
		return nil, formatAPIError("PATCH", path, status, respBody)
	}
	return respBody, nil
}

func (c *HubClient) Delete(ctx context.Context, path string) error {
	respBody, status, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if status == http.StatusAccepted {
		return pendingApprovalError("DELETE", path, respBody)
	}
	if status == http.StatusNotFound || status == http.StatusNoContent || status == http.StatusOK {
		return nil
	}
	return formatAPIError("DELETE", path, status, respBody)
}
