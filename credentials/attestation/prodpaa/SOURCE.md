# Production PAA certificates

These are the product attestation authority (PAA) root certificates of the
Matter Distributed Compliance Ledger, as mirrored in the Matter SDK
([connectedhomeip](https://github.com/project-chip/connectedhomeip),
Apache-2.0) under `credentials/production/paa-root-certs` at commit
`c55ddad4` (2026-11-13): 73 certificates, kept in DER under the SDK's file
names (the one PAA the SDK holds only as PEM, NXP's, was converted to DER).

To refresh them, copy the `.der` files of a newer SDK checkout here (and
convert any PEM-only ones with `openssl x509 -outform DER`), or fetch the
PAAs from the ledger.
