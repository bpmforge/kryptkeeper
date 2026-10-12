# Third-party licenses

Generated 2026-09-11 for W20-03 (open-source readiness) via:

```
go install github.com/google/go-licenses@latest
go-licenses csv ./cmd/...
```

This covers Go module dependencies bundled into the `cmd/kryptkeeper` binary
only. **npm/frontend (`ui/`) dependencies are out of scope for this file** —
that inventory is a separate ticket.

`go-licenses` could not automatically classify one module:

- `modernc.org/mathutil` ships a `LICENSE` file (BSD-3-Clause-style, the
  standard modernc.org/cznic license text) that go-licenses' classifier did
  not match by name/content; manually confirmed as BSD-3-Clause.

## Dependencies

| Module | License | Source |
|---|---|---|
| `github.com/Azure/go-ntlmssp` | MIT | https://github.com/Azure/go-ntlmssp/blob/v0.1.1/LICENSE |
| `github.com/aws/aws-sdk-go-v2` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/v1.41.6/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/config` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/config/v1.32.15/config/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/credentials` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/credentials/v1.19.14/credentials/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/feature/ec2/imds/v1.18.21/feature/ec2/imds/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/configsources/v1.4.22/internal/configsources/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/endpoints/v2.7.22/internal/endpoints/v2/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/internal/sync/singleflight` | BSD-3-Clause | https://github.com/aws/aws-sdk-go-v2/blob/v1.41.6/internal/sync/singleflight/LICENSE |
| `github.com/aws/aws-sdk-go-v2/service/acm` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/acm/v1.38.2/service/acm/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/accept-encoding/v1.13.7/service/internal/accept-encoding/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/presigned-url/v1.13.21/service/internal/presigned-url/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/kms` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/kms/v1.50.4/service/kms/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/signin` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/signin/v1.0.9/service/signin/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/sso` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sso/v1.30.15/service/sso/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ssooidc/v1.35.19/service/ssooidc/LICENSE.txt |
| `github.com/aws/aws-sdk-go-v2/service/sts` | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sts/v1.41.10/service/sts/LICENSE.txt |
| `github.com/aws/smithy-go` | Apache-2.0 | https://github.com/aws/smithy-go/blob/v1.25.0/LICENSE |
| `github.com/aws/smithy-go/internal/sync/singleflight` | BSD-3-Clause | https://github.com/aws/smithy-go/blob/v1.25.0/internal/sync/singleflight/LICENSE |
| `github.com/beevik/etree` | BSD-2-Clause | https://github.com/beevik/etree/blob/v1.6.0/LICENSE |
| `github.com/cloudflare/circl` | BSD-3-Clause | https://github.com/cloudflare/circl/blob/v1.6.3/LICENSE |
| `github.com/dustin/go-humanize` | MIT | https://github.com/dustin/go-humanize/blob/v1.0.1/LICENSE |
| `github.com/go-asn1-ber/asn1-ber` | MIT | https://github.com/go-asn1-ber/asn1-ber/blob/v1.5.8/LICENSE |
| `github.com/go-ldap/ldap/v3` | MIT | https://github.com/go-ldap/ldap/blob/v3.4.14/v3/LICENSE |
| `github.com/go-pdf/fpdf` | MIT | https://github.com/go-pdf/fpdf/blob/v0.9.0/LICENSE |
| `github.com/google/jsonschema-go/jsonschema` | MIT | https://github.com/google/jsonschema-go/blob/v0.4.2/LICENSE |
| `github.com/google/uuid` | BSD-3-Clause | https://github.com/google/uuid/blob/v1.6.0/LICENSE |
| `github.com/jackc/pgpassfile` | MIT | https://github.com/jackc/pgpassfile/blob/v1.0.0/LICENSE |
| `github.com/jackc/pgservicefile` | MIT | https://github.com/jackc/pgservicefile/blob/5a60cdf6a761/LICENSE |
| `github.com/jackc/pgx/v5` | MIT | https://github.com/jackc/pgx/blob/v5.9.1/LICENSE |
| `github.com/jackc/puddle/v2` | MIT | https://github.com/jackc/puddle/blob/v2.2.2/LICENSE |
| `github.com/jonboulle/clockwork` | Apache-2.0 | https://github.com/jonboulle/clockwork/blob/v0.5.0/LICENSE |
| `github.com/mark3labs/mcp-go` | MIT | https://github.com/mark3labs/mcp-go/blob/v0.55.0/LICENSE |
| `github.com/mattermost/xml-roundtrip-validator` | Apache-2.0 | https://github.com/mattermost/xml-roundtrip-validator/blob/v0.1.0/LICENSE.txt |
| `github.com/mattn/go-isatty` | MIT | https://github.com/mattn/go-isatty/blob/v0.0.24/LICENSE |
| `github.com/ncruces/go-strftime` | MIT | https://github.com/ncruces/go-strftime/blob/v1.0.0/LICENSE |
| `github.com/remyoudompheng/bigfft` | BSD-3-Clause | https://github.com/remyoudompheng/bigfft/blob/24d4a6f8daec/LICENSE |
| `github.com/russellhaering/gosaml2` | Apache-2.0 | https://github.com/russellhaering/gosaml2/blob/v0.11.0/LICENSE |
| `github.com/russellhaering/goxmldsig` | Apache-2.0 | https://github.com/russellhaering/goxmldsig/blob/v1.6.0/LICENSE |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | https://github.com/santhosh-tekuri/jsonschema/blob/v6.0.2/LICENSE |
| `github.com/smallstep/pkcs7` | MIT | https://github.com/smallstep/pkcs7/blob/v0.2.3/LICENSE |
| `github.com/smallstep/pkcs7/internal/cryptobyte` | BSD-3-Clause | https://github.com/smallstep/pkcs7/blob/v0.2.3/internal/cryptobyte/LICENSE |
| `github.com/spf13/cast` | MIT | https://github.com/spf13/cast/blob/v1.7.1/LICENSE |
| `github.com/spiffe/go-spiffe/v2/proto/spiffe/workload` | Apache-2.0 | https://github.com/spiffe/go-spiffe/blob/v2.8.1/LICENSE |
| `github.com/tink-crypto/tink-go/v2/kwp/subtle` | Apache-2.0 | https://github.com/tink-crypto/tink-go/blob/v2.8.0/LICENSE |
| `github.com/yosida95/uritemplate/v3` | BSD-3-Clause | https://github.com/yosida95/uritemplate/blob/v3.0.2/LICENSE |
| `go.mozilla.org/pkcs7` | MIT | https://github.com/mozilla-services/pkcs7/blob/v0.10.0/LICENSE |
| `golang.org/x/crypto` | BSD-3-Clause | https://cs.opensource.google/go/x/crypto/+/v0.54.0:LICENSE |
| `golang.org/x/net` | BSD-3-Clause | https://cs.opensource.google/go/x/net/+/v0.57.0:LICENSE |
| `golang.org/x/sync/semaphore` | BSD-3-Clause | https://cs.opensource.google/go/x/sync/+/v0.22.0:LICENSE |
| `golang.org/x/sys` | BSD-3-Clause | https://cs.opensource.google/go/x/sys/+/v0.47.0:LICENSE |
| `golang.org/x/text` | BSD-3-Clause | https://cs.opensource.google/go/x/text/+/v0.40.0:LICENSE |
| `google.golang.org/genproto/googleapis/rpc/status` | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/3dc84a4a5aaa/googleapis/rpc/LICENSE |
| `google.golang.org/grpc` | Apache-2.0 | https://github.com/grpc/grpc-go/blob/v1.83.1/LICENSE |
| `google.golang.org/protobuf` | BSD-3-Clause | https://github.com/protocolbuffers/protobuf-go/blob/v1.36.11/LICENSE |
| `modernc.org/libc` | MIT | https://gitlab.com/cznic/libc/blob/v1.75.6/LICENSE-3RD-PARTY.md |
| `modernc.org/mathutil` | BSD-3-Clause (manually confirmed) | Unknown |
| `modernc.org/memory` | BSD-3-Clause | https://gitlab.com/cznic/memory/blob/v1.12.1/LICENSE-GO |
| `modernc.org/sqlite` | BSD-3-Clause | https://gitlab.com/cznic/sqlite/blob/v1.58.0/LICENSE |
| `software.sslmate.com/src/go-pkcs12` | BSD-3-Clause | https://github.com/SSLMate/go-pkcs12/blob/v0.7.3/LICENSE |

## Frontend font: Geist (SIL OFL-1.1)

The UI bundles the Geist Variable font via the npm package
`@fontsource-variable/geist` (5.2.8). The `.woff2` files are emitted into
`ui/dist/assets`. Geist is Copyright 2024 The Geist Project Authors
(https://github.com/vercel/geist-font.git) and licensed under the SIL Open
Font License, Version 1.1 (https://openfontlicense.org). The full license text
is shipped with the app at `/licenses/Geist-OFL-1.1.txt`
(source: `ui/public/licenses/Geist-OFL-1.1.txt`, copied unmodified from the
package's `LICENSE`). The font files are redistributed unmodified and are not
sold on their own.

## HashiCorp modules (MPL-2.0) in terraform-provider-kryptkeeper

The Terraform provider (`terraform-provider-kryptkeeper/`) links these
HashiCorp Go modules, all **unmodified**:

| Module | License |
|---|---|
| `github.com/hashicorp/terraform-plugin-framework` | MPL-2.0 |
| `github.com/hashicorp/terraform-plugin-go` | MPL-2.0 |
| `github.com/hashicorp/terraform-plugin-log` | MPL-2.0 |
| `github.com/hashicorp/terraform-registry-address` | MPL-2.0 |
| `github.com/hashicorp/terraform-svchost` | MPL-2.0 |
| `github.com/hashicorp/go-plugin` | MPL-2.0 |
| `github.com/hashicorp/go-uuid` | MPL-2.0 |
| `github.com/hashicorp/yamux` | MPL-2.0 |
| `github.com/hashicorp/go-hclog` | MIT |

Source availability (MPL-2.0 section 3.2): the source of each MPL-covered
module, at the exact versions pinned in `terraform-provider-kryptkeeper/go.mod`
and `go.sum`, is available from its upstream repository at
`https://github.com/hashicorp/<module>` (and via the Go module proxy). No
modifications have been made. The MPL-2.0 text is at
https://www.mozilla.org/MPL/2.0/. Kryptkeeper's own source in the provider
remains under the repository license; MPL-2.0 is file-level copyleft and does
not extend to it. `github.com/hashicorp/go-uuid` (MPL-2.0) is also an indirect
dependency of the main module.
