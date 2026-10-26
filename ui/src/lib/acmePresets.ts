// Named ACME directories for the issuer wizard. Data only. Each URL was checked
// against the CA's own documentation (W36-13). DigiCert ACME is not listed: its
// directory URL is generated per account in CertCentral, so there is no fixed
// public URL to preset.
export type AcmePreset = {
  id: string;
  label: string;
  directoryUrl: string;
  eabRequired: boolean;
  note: string;
};

export const ACME_PRESETS: AcmePreset[] = [
  {
    id: "letsencrypt",
    label: "Let's Encrypt (production)",
    directoryUrl: "https://acme-v02.api.letsencrypt.org/directory",
    eabRequired: false,
    note: "Public certificates, rate limited. Use staging while testing.",
  },
  {
    id: "letsencrypt-staging",
    label: "Let's Encrypt (staging)",
    directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
    eabRequired: false,
    note: "Untrusted test certificates with relaxed limits.",
  },
  {
    id: "zerossl",
    label: "ZeroSSL",
    directoryUrl: "https://acme.zerossl.com/v2/DV90",
    eabRequired: true,
    note: "Create EAB credentials in the ZeroSSL dashboard first.",
  },
  {
    id: "google",
    label: "Google Trust Services",
    directoryUrl: "https://dv.acme-v02.api.pki.goog/directory",
    eabRequired: true,
    note: "EAB keys come from gcloud and expire if unused for 7 days.",
  },
  {
    id: "sslcom",
    label: "SSL.com (ECDSA)",
    directoryUrl: "https://acme.ssl.com/sslcom-dv-ecc",
    eabRequired: true,
    note: "Use https://acme.ssl.com/sslcom-dv-rsa instead if you need RSA keys.",
  },
  {
    id: "buypass",
    label: "Buypass Go SSL",
    directoryUrl: "https://api.buypass.com/acme/directory",
    eabRequired: false,
    note: "No wildcards, up to 5 names per certificate.",
  },
  {
    id: "sectigo",
    label: "Sectigo ACME (DV)",
    directoryUrl: "https://acme.sectigo.com/v2/DV",
    eabRequired: true,
    note: "EAB comes from Sectigo Certificate Manager. OV and EV use a different URL.",
  },
];
