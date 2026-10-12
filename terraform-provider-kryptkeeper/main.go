// terraform-provider-kryptkeeper implements a Terraform provider for
// managing certificate authorities, certificates, and templates in
// a Kryptkeeper Hub.
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"terraform-provider-kryptkeeper/internal/provider"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/kryptkeeper/kryptkeeper",
	}
	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err)
	}
}
