module kryptkeeper

go 1.27.0

toolchain go1.27.3

// SQL Server's default TLS certificate has a negative serial number. Go 1.23+
// refuses to parse such a certificate, which made the handshake to every default
// SQL Server fail before the scanner could record it (W34-20, found against a
// real engine). Discovery must inspect what servers actually present; this is
// parse leniency only and verification rules are unchanged.
godebug x509negativeserial=1

require (
	github.com/ThalesGroup/crypto11 v1.6.1
	github.com/aws/aws-sdk-go-v2 v1.41.6
	github.com/aws/aws-sdk-go-v2/config v1.32.15
	github.com/aws/aws-sdk-go-v2/service/acm v1.38.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.4
	github.com/beevik/etree v1.6.0
	github.com/cloudflare/circl v1.6.3
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/go-pdf/fpdf v0.9.0
	github.com/jackc/pgx/v5 v5.9.2
	github.com/jcmturner/goidentity/v6 v6.0.1
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mark3labs/mcp-go v0.55.0
	github.com/russellhaering/gosaml2 v0.11.0
	github.com/russellhaering/goxmldsig v1.6.0
	github.com/smallstep/pkcs7 v0.2.3
	github.com/spiffe/go-spiffe/v2 v2.8.1
	github.com/tink-crypto/tink-go/v2 v2.8.0
	go.mozilla.org/pkcs7 v0.10.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.48.0
	google.golang.org/grpc v1.83.2
	modernc.org/sqlite v1.58.0
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require github.com/tetratelabs/wazero v1.12.0

require (
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.46.13
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.14
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.10 // indirect
	github.com/aws/smithy-go v1.25.0
	github.com/bpmforge/kryptkeeper/sdk/delivery-go v0.0.0-00010101000000-000000000000
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/miekg/pkcs11 v1.1.2
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	github.com/spf13/cast v1.7.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace github.com/bpmforge/kryptkeeper/sdk/delivery-go => ./sdk/delivery-go
