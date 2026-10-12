# cosign interop fixtures (W20-24)

Public material only, made with cosign v3.1.3 so the hub's verifier is
tested against real cosign output rather than our reading of its format:

- `cosign-interop.pub.txt`: the public half of a throwaway key from
  `cosign generate-key-pair`. The private half was deleted after signing.
- `manifest.json.bundle`: `cosign sign-blob --key ... --bundle ...
  --use-signing-config=false --tlog-upload=false manifest.json` (the v3
  default format).
- `manifest.json.sig`: the same with `--new-bundle-format=false
  --output-signature` (the bare base64 form).

`cosign verify-blob --key cosign-interop.pub.txt --bundle manifest.json.bundle
--insecure-ignore-tlog=true manifest.json` reports Verified OK.
