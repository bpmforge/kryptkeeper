// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// Elastic Load Balancing v2 is a query-protocol API (form body, XML reply),
// not JSON.
const elbVersion = "2015-12-01"

// elbCall posts the form, signed for service elasticloadbalancing, and
// returns the XML reply of a 200. Error replies carry <Error><Code>.
func (a *aws) elbCall(region, action string, params url.Values) ([]byte, error) {
	params.Set("Action", action)
	params.Set("Version", elbVersion)
	resp, err := a.send(action, "elasticloadbalancing", region, abi.HTTPRequest{
		Method: "POST", URL: hostFor("elasticloadbalancing", region), Body: []byte(params.Encode()),
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		var e struct {
			Code string `xml:"Error>Code"`
		}
		_ = xml.Unmarshal(resp.Body, &e)
		if !errTypePattern.MatchString(e.Code) {
			e.Code = ""
		}
		return nil, fmt.Errorf("%s: HTTP %d %s", action, resp.Status, e.Code)
	}
	return resp.Body, nil
}

type albBinding struct {
	a        *aws
	region   string
	listener string
}

// current is the listener's default certificate ARN.
func (b albBinding) current() (string, error) {
	body, err := b.a.elbCall(b.region, "DescribeListeners", url.Values{"ListenerArns.member.1": {b.listener}})
	if err != nil {
		return "", err
	}
	var r struct {
		Certs []string `xml:"DescribeListenersResult>Listeners>member>Certificates>member>CertificateArn"`
	}
	if xml.Unmarshal(body, &r) != nil {
		return "", errors.New("DescribeListeners: response unreadable")
	}
	if len(r.Certs) == 0 {
		return "", errors.New("listener has no default certificate (is it an HTTPS/TLS listener?)")
	}
	return r.Certs[0], nil
}

// bind sets the default certificate; ModifyListener with an unchanged ARN is
// harmless, so it is always sent.
func (b albBinding) bind(arn string) error {
	_, err := b.a.elbCall(b.region, "ModifyListener", url.Values{
		"ListenerArn": {b.listener}, "Certificates.member.1.CertificateArn": {arn},
	})
	return err
}
