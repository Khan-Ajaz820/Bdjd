# Trusted Root CA Certificates

This folder contains **bundled trusted root CA certificates** that the app uses
to validate PDF digital signature certificate chains **fully offline**.

## How to add certificates

Drop any `.cer`, `.crt`, `.pem`, or `.der` certificate file into this folder.
No renaming is needed — the app loads every file with those extensions at runtime.

The folder can ship **empty** (except this README). When no roots are present the
app will still run and report:

> "Trust store is empty — no trusted root CAs loaded. Issuer not in trusted list."

## Recommended certificates for Indian government PDFs (Aadhaar, DigiLocker, etc.)

Download the following from the **Controller of Certifying Authorities (CCA) India**:
👉 https://cca.gov.in/root-certifying-authority.html

| Certificate                          | Purpose                                      |
|--------------------------------------|----------------------------------------------|
| CCA India 2014 Root                  | Root CA for all Indian DSC issuers           |
| CCA India 2022 Root                  | Newer root CA                                |
| NIC CA 2017 / NIC CA 2021            | Intermediate CA used by NIC-issued DSCs      |
| eMudhra CA / Sify CA / NSDL CA etc.  | Intermediate CAs for commercial DSC issuers  |

### Steps

1. Visit https://cca.gov.in/root-certifying-authority.html
2. Download the `.cer` or `.crt` files for the root and intermediate CAs.
3. Copy them into this folder (`app/src/main/assets/trusted_roots/`).
4. Rebuild the app — the certificates will be bundled automatically.

Alternatively, use the **"Import CA Cert"** button in the app to import a
certificate at runtime without rebuilding. Runtime-imported certs are stored in
the app's private internal storage and persist across app restarts.

## Security note

Only add certificates from **official, trusted sources** (e.g. cca.gov.in).
Adding a malicious root CA would allow an attacker to forge signatures that
appear valid to this app.
