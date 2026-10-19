// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/revsign"
)

const maxShards = 256

var oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}

// shardSpace is the serial space the shards partition: serials are random
// 128-bit values.
var shardSpace = new(big.Int).Lsh(big.NewInt(1), 128)

// ShardIndex maps a serial to a shard in [0,n) by range over the 128-bit
// serial space. n <= 1 or a negative serial gives 0; serials above 2^128-1
// land in the last shard.
func ShardIndex(serial *big.Int, n int) int {
	if n <= 1 || serial == nil || serial.Sign() < 0 {
		return 0
	}
	idx := new(big.Int).Mul(serial, big.NewInt(int64(n)))
	idx.Rsh(idx, 128)
	if !idx.IsInt64() || idx.Int64() >= int64(n) {
		return n - 1
	}
	return int(idx.Int64())
}

// ShardCountFromEnv reads KRYPTKEEPER_CRL_SHARDS. Unset, invalid or < 1 means
// 1 (no sharding; invalid values are logged); more than 256 is capped.
func ShardCountFromEnv() int {
	v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_CRL_SHARDS"))
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		logging.Infof("invalid KRYPTKEEPER_CRL_SHARDS %q: sharding off", v)
		return 1
	}
	return min(n, maxShards)
}

// ShardURL is where shard i of caID's CRL is served.
func ShardURL(base, caID string, shard int) string {
	return base + "/crl/" + caID + "/s" + strconv.Itoa(shard) + ".crl"
}

// crlRequest is a parsed /crl/ path. Shard is -1 when the request is not for a shard.
type crlRequest struct {
	CAID  string
	Shard int
	Delta bool
}

// parseCRLRequest recognises "/crl/{ca}/s{i}.crl" and otherwise defers to
// parseCRLPath (full and delta CRLs).
func parseCRLRequest(p string) (crlRequest, bool) {
	if rest, ok := strings.CutPrefix(p, "/crl/"); ok {
		if id, tail, found := strings.Cut(rest, "/s"); found && strings.HasSuffix(tail, ".crl") {
			digits := strings.TrimSuffix(tail, ".crl")
			i, err := strconv.Atoi(digits)
			if err == nil && i >= 0 && digits == strconv.Itoa(i) && validCAID(id) {
				return crlRequest{CAID: id, Shard: i}, true
			}
		}
	}
	caID, delta, ok := parseCRLPath(p)
	if !ok {
		return crlRequest{}, false
	}
	return crlRequest{CAID: caID, Shard: -1, Delta: delta}, true
}

// idpExtension is the critical Issuing Distribution Point (RFC 5280 5.2.5)
// naming url as the CRL's distributionPoint.
func idpExtension(url string) pkix.Extension {
	name := tlv(0xA0, tlv(0xA0, tlv(0x86, []byte(url)))) // distributionPoint [0] { fullName [0] { URI [6] } }
	return pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: tlv(0x30, name)}
}

// WithShards turns on IDP-partitioned shard CRLs. n <= 1 or an empty
// publicBase leaves sharding off. Call before serving.
func (g *Generator) WithShards(n int, publicBase string) *Generator {
	publicBase = strings.TrimRight(publicBase, "/")
	if n > 1 && publicBase != "" {
		g.shardN = min(n, maxShards)
		g.shardBase = publicBase
	}
	return g
}

// GenerateAllShards signs every shard of caID's CRL from ONE revocation
// listing, so the cost of a regeneration is one DB scan plus n signatures.
func (g *Generator) GenerateAllShards(caID string) ([]*GeneratedCRL, error) {
	out, events, err := g.generateAllShards(caID)
	for _, ev := range events {
		g.emit(ev)
	}
	if err != nil {
		g.emit(Event{Action: ActionGenerate, CAID: caID, Detail: err.Error(), Failure: true})
		return nil, err
	}
	return out, nil
}

func (g *Generator) generateAllShards(caID string) ([]*GeneratedCRL, []Event, error) {
	if g.shardN <= 1 {
		return nil, nil, fmt.Errorf("CRL sharding is not enabled")
	}
	caCert, signer, err := g.caFunc(caID)
	if err != nil {
		return nil, nil, fmt.Errorf("ca lookup: %w", err)
	}
	now := time.Now().UTC() // before listing, as for the full CRL
	revoked, err := g.revokedFunc(caID)
	if err != nil {
		return nil, nil, fmt.Errorf("revoked certs lookup: %w", err)
	}
	revoked = withoutSerial(revoked, caCert.SerialNumber)
	parts := make([][]RevokedCert, g.shardN)
	for _, rc := range revoked {
		i := ShardIndex(rc.SerialNumber, g.shardN)
		parts[i] = append(parts[i], rc)
	}

	out := make([]*GeneratedCRL, g.shardN)
	events := make([]Event, 0, g.shardN)
	for i := range parts {
		number, err := g.nextNumber(fmt.Sprintf("%s/s%d", caID, i))
		if err != nil {
			return nil, nil, err
		}
		template := &x509.RevocationList{
			Number:                    number,
			ThisUpdate:                now,
			NextUpdate:                now.Add(g.validity),
			RevokedCertificateEntries: toRevocationEntries(parts[i]),
			ExtraExtensions:           []pkix.Extension{idpExtension(ShardURL(g.shardBase, caID, i))},
		}
		der, err := revsign.CreateRevocationList(rand.Reader, template, caCert, signer)
		if err != nil {
			return nil, nil, fmt.Errorf("create shard %d CRL: %w", i, err)
		}
		out[i] = &GeneratedCRL{
			CAAID:      caID,
			DER:        der,
			PEM:        pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}),
			Number:     number,
			ThisUpdate: now,
			NextUpdate: template.NextUpdate,
		}
		events = append(events, Event{Action: ActionGenerate, CAID: caID,
			Detail: fmt.Sprintf("shard=%d/%d number=%s entries=%d", i, g.shardN, number, len(parts[i]))})
	}

	g.mu.Lock()
	// A slower, older generation must not replace a newer one.
	if cur := g.shards[caID]; len(cur) == 0 || cur[0].Number.Cmp(out[0].Number) < 0 {
		g.shards[caID] = out
	}
	g.mu.Unlock()
	return out, events, nil
}

// GetShard returns the cached, unexpired shard i of caID, or nil.
func (g *Generator) GetShard(caID string, i int) *GeneratedCRL {
	g.mu.RLock()
	defer g.mu.RUnlock()
	set := g.shards[caID]
	if i < 0 || i >= len(set) || !time.Now().Before(set[i].NextUpdate) {
		return nil
	}
	return set[i]
}
