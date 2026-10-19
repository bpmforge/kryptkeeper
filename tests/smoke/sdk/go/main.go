// W32-03: Go SDK contract smoke. Uses ONLY the generated client (sdk/api-go);
// the spec declares no response schemas, so bodies are read from the raw
// *http.Response the generated Execute() returns.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	api "github.com/bpmforge/kryptkeeper/sdk/api-go/kryptkeeperapi"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[sdk-smoke go] FAIL "+format+"\n", a...)
	os.Exit(1)
}

func body(res *http.Response) []byte {
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		fail("read body: %v", err)
	}
	return b
}

func main() {
	hub, token, caID, tplID, csrDir := os.Getenv("HUB_URL"), os.Getenv("HUB_TOKEN"), os.Getenv("CA_ID"), os.Getenv("TEMPLATE_ID"), os.Getenv("CSR_DIR")
	if hub == "" || token == "" || caID == "" || tplID == "" || csrDir == "" {
		fail("HUB_URL, HUB_TOKEN, CA_ID, TEMPLATE_ID, CSR_DIR must be set")
	}
	cfg := api.NewConfiguration()
	cfg.Servers = api.ServerConfigurations{{URL: hub + "/api/v1"}}
	client := api.NewAPIClient(cfg)
	ctx := context.WithValue(context.Background(), api.ContextAccessToken, token)

	issued := map[string]bool{}
	var first string
	for i := 1; i <= 5; i++ {
		csr, err := os.ReadFile(filepath.Join(csrDir, fmt.Sprintf("csr-%d.pem", i)))
		if err != nil {
			fail("read csr: %v", err)
		}
		res, err := client.CertificatesAPI.IssueCertificate(ctx).
			IssueCertificateRequest(*api.NewIssueCertificateRequest(caID, tplID, string(csr))).Execute()
		if err != nil {
			fail("issue %d: %v", i, err)
		}
		raw := body(res)
		if res.StatusCode != 201 {
			fail("issue %d: status %d (want 201): %s", i, res.StatusCode, raw)
		}
		var out struct {
			Data struct {
				Fingerprint string `json:"fingerprint_sha256"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.Data.Fingerprint == "" {
			fail("issue %d: no fingerprint in %s", i, raw)
		}
		issued[out.Data.Fingerprint] = true
		if first == "" {
			first = out.Data.Fingerprint
		}
	}

	seen := map[string]bool{}
	requests, cursor := 0, int32(0)
	for {
		req := client.CertificatesAPI.ListCertificates(ctx).Limit(2)
		if cursor > 0 {
			req = req.Cursor(cursor)
		}
		res, err := req.Execute()
		if err != nil {
			fail("list: %v", err)
		}
		raw := body(res)
		requests++
		var page struct {
			Data []struct {
				Fingerprint string `json:"fingerprint_sha256"`
			} `json:"data"`
			Meta struct {
				NextCursor *string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			fail("list: bad json: %v", err)
		}
		for _, c := range page.Data {
			seen[c.Fingerprint] = true
		}
		if page.Meta.NextCursor == nil || *page.Meta.NextCursor == "" {
			break
		}
		n, err := strconv.Atoi(*page.Meta.NextCursor)
		if err != nil {
			fail("list: non-integer next_cursor %q", *page.Meta.NextCursor)
		}
		cursor = int32(n)
		if requests > 100 {
			fail("list: pagination did not terminate")
		}
	}
	if requests < 3 {
		fail("list: %d requests, want >= 3 (>= 2 pages)", requests)
	}
	for fp := range issued {
		if !seen[fp] {
			fail("list: issued fingerprint %s not seen across pages", fp)
		}
	}

	rev := api.NewRevokeCertificateRequest()
	rev.SetReasonCode(1)
	_, res, err := client.CertificatesAPI.RevokeCertificate(ctx, first).RevokeCertificateRequest(*rev).Execute()
	if err != nil {
		fail("revoke: %v", err)
	}
	raw := body(res)
	if res.StatusCode != 200 {
		fail("revoke: status %d (want 200, no approval gate expected): %s", res.StatusCode, raw)
	}
	res, err = client.CertificatesAPI.GetCertificate(ctx, first).Execute()
	if err != nil {
		fail("get: %v", err)
	}
	var got struct {
		Data struct {
			RenewalStatus string `json:"renewal_status"`
			RevokedAt     string `json:"revoked_at"`
		} `json:"data"`
	}
	raw = body(res)
	if err := json.Unmarshal(raw, &got); err != nil || got.Data.RenewalStatus != "revoked" || got.Data.RevokedAt == "" {
		fail("get after revoke: renewal_status %q, body %s", got.Data.RenewalStatus, raw)
	}
	fmt.Printf("[sdk-smoke go] ok: issued 5, listed in %d requests, revoked 1\n", requests)
}
