// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// The CloudFront control plane is global and signed for us-east-1.
const cfRegion = "us-east-1"

var arnElement = regexp.MustCompile(`<ACMCertificateArn>([^<]*)</ACMCertificateArn>`)

type cfBinding struct {
	a  *aws
	id string
}

func (b cfBinding) path() string {
	return "https://cloudfront.amazonaws.com/2020-05-31/distribution/" + b.id + "/config"
}

// get returns the ETag and the raw config document. The document is never
// re-marshalled: a round trip would drop fields CloudFront added.
func (b cfBinding) get() (etag string, doc []byte, err error) {
	resp, err := b.a.send("GetDistributionConfig", "cloudfront", cfRegion, abi.HTTPRequest{Method: "GET", URL: b.path()})
	if err != nil {
		return "", nil, err
	}
	if resp.Status != 200 {
		return "", nil, fmt.Errorf("GetDistributionConfig: HTTP %d", resp.Status)
	}
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "ETag") {
			etag = v
		}
	}
	if etag == "" {
		return "", nil, errors.New("GetDistributionConfig: no ETag in response")
	}
	return etag, resp.Body, nil
}

func arnSpan(doc []byte) (start, end int, arn string, err error) {
	loc := arnElement.FindSubmatchIndex(doc)
	if loc == nil {
		return 0, 0, "", errors.New("distribution has no ACMCertificateArn (it must already use an ACM certificate)")
	}
	arn = string(doc[loc[2]:loc[3]])
	if !acmARNPattern.MatchString(arn) {
		return 0, 0, "", errors.New("distribution ACMCertificateArn is not an ACM ARN")
	}
	return loc[2], loc[3], arn, nil
}

func (b cfBinding) current() (string, error) {
	_, doc, err := b.get()
	if err != nil {
		return "", err
	}
	_, _, arn, err := arnSpan(doc)
	return arn, err
}

// bind replaces only the text inside the ACMCertificateArn element and PUTs
// the document back under If-Match. An already-bound ARN sends nothing (a
// PUT would redeploy the distribution for no change).
func (b cfBinding) bind(arn string) error {
	if !acmARNPattern.MatchString(arn) {
		return errors.New("not an ACM certificate ARN")
	}
	etag, doc, err := b.get()
	if err != nil {
		return err
	}
	s, e, have, err := arnSpan(doc)
	if err != nil {
		return err
	}
	if have == arn {
		return nil
	}
	body := bytes.Join([][]byte{doc[:s], []byte(arn), doc[e:]}, nil)
	resp, err := b.a.send("UpdateDistribution", "cloudfront", cfRegion, abi.HTTPRequest{
		Method: "PUT", URL: b.path(), Body: body,
		Headers: map[string]string{"If-Match": etag, "Content-Type": "application/xml"},
	})
	if err != nil {
		return err
	}
	switch resp.Status {
	case 200:
		return nil
	case 412:
		return errors.New("distribution changed during update")
	}
	return fmt.Errorf("UpdateDistribution: HTTP %d", resp.Status)
}
