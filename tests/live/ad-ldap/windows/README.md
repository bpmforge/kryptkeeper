# W24-27 - adcs_live vs a Windows DC

`run.sh` points the hub's `adcs_live` inventory source at an already-provisioned
Windows Server DC and asserts: sync 1 imports K certificates, sync 2 adds 0
(`synced == 0`, `skipped == K`), a wrong bind password fails cleanly without
leaking the secret, and the first source is unaffected. No container, no Samba.

## What K means

`adcs_live` binds over LDAP and runs a paged search for the `userCertificate`
attribute (default filter `(userCertificate=*)`) under `search_base`. K is the
number of DISTINCT certificates in those attributes (the same cert on two
objects dedupes by fingerprint). It is NOT the CA's issued-row count.

## Lab prerequisites (operator-provided; nothing here names a real host)

- Windows Server 2022 DC with an AD CS Enterprise CA.
- A certificate template with "Publish certificate in Active Directory"
  enabled, so issued certs land in `userCertificate` on user/computer objects.
- A service account with read access to `userCertificate` (Domain Users default).
- LDAPS reachable from the machine running the hub, and the DC's LDAPS chain
  trusted by that machine. `adcs_live` uses the SYSTEM trust store (there is no
  per-source CA setting): import the lab root CA into the host trust store or
  the sync fails with an x509 error (trap).

## PowerShell (documentation only; run on the DC / a domain member)

Issue K certs, for example as K distinct test users:

    Get-Certificate -Template User -CertStoreLocation Cert:\CurrentUser\My

(or `certreq`). Then count what the hub should see, users and computers:

    (Get-ADUser -Filter * -SearchBase "<base>" -Properties userCertificate |
      ForEach-Object { $_.userCertificate }).Count
    (Get-ADComputer -Filter * -SearchBase "<base>" -Properties userCertificate |
      ForEach-Object { $_.userCertificate }).Count

Sum them (distinct certs only) and pass the total as `KK_ADCS_EXPECTED_K`; pass
the same figure as `KK_ADCS_DC_COUNT` to record the independent DC-side count.

## Run

    export KK_ADCS_LDAP_URL='ldaps://<dc-fqdn>:636'
    export KK_ADCS_BIND_DN='<bind dn or UPN>'
    export KK_ADCS_BIND_PASSWORD='<read from your secret store>'
    export KK_ADCS_SEARCH_BASE='<dn>'
    export KK_ADCS_EXPECTED_K=<K>
    KK_ADCS_DC_OS='Windows Server 2022' KK_WRITE_RESULTS=1 \
      bash tests/live/ad-ldap/windows/run.sh

Optional: `KK_ADCS_FILTER`, `KK_ADCS_PAGE_SIZE` (default 1000; set 100 in one
run when K > 100 to prove paging), `KK_ADCS_DC_COUNT`, `KK_KEEP=1`.
With any required variable missing the script exits 2 and prints a usage line.
The password is read from the environment only (never echoed, never in argv).
`KK_WRITE_RESULTS=1` writes `docs/release/LIVE_RESULTS_ADCS_v0.12.md`; review and
commit it. Port 8097 must be free.
