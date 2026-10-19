// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package cloudinventory_live_test is a helper for run.sh: it imports K
// self-signed ECDSA certificates into an ACM emulator and prints one
// "ARN=<arn>" line per certificate. Skipped unless KK_LIVE_CLOUD_INVENTORY=1.
// Keys are generated in memory and never written to disk.
package cloudinventory_live_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func TestImportCerts(t *testing.T) {
	if os.Getenv("KK_LIVE_CLOUD_INVENTORY") != "1" {
		t.Skip("set KK_LIVE_CLOUD_INVENTORY=1 (see run.sh) to import certificates into an ACM emulator")
	}
	if os.Getenv("AWS_ENDPOINT_URL") == "" {
		t.Fatal("AWS_ENDPOINT_URL must point at the emulator; refusing to fall through to real AWS")
	}
	count, err := strconv.Atoi(os.Getenv("KK_IMPORT_COUNT"))
	if err != nil || count < 1 {
		t.Fatal("KK_IMPORT_COUNT must be a positive integer")
	}
	region := os.Getenv("KK_IMPORT_REGION")
	if region == "" {
		t.Fatal("KK_IMPORT_REGION is required")
	}
	// Distinct names per region so two regions never collide.
	prefix := os.Getenv("KK_IMPORT_PREFIX")
	if prefix == "" {
		prefix = "acm-uat"
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatal(err)
	}
	client := acm.NewFromConfig(cfg)
	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("%s-%d.kryptkeeper.uat.local", prefix, i)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano() + int64(i)),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name, "www." + name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		out, err := client.ImportCertificate(ctx, &acm.ImportCertificateInput{
			Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		})
		if err != nil {
			t.Fatalf("ImportCertificate %d: %v", i, err)
		}
		fmt.Printf("ARN=%s\n", aws.ToString(out.CertificateArn))
	}
}
