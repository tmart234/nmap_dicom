# nmap_dicom
PR work for nmap dicom

## Overview
### Vendor & Version Fingerprinting
The script extracts two fields from the User Information item of the A-ASSOCIATE-AC PDU:

Implementation Class UID (item type 0x52) — a mandatory OID registered to the organization that built the software. Can be looked up in public OID registries (e.g., oid-base.com).
Implementation Version Name (item type 0x55) — an optional 16-character string that often identifies the actual toolkit or product and its version.

#### Toolkit-first resolution:
In practice, device manufacturers (GE, Philips, Siemens) often ship commercial toolkits (DCMTK, MergeCOM3, dcm4che) without overriding the default 0x55 string. Since a pentester cares about the code actually listening on the wire — that's where the CVEs and parser bugs live — the script prioritizes the toolkit identity from 0x55 as the primary vendor. When 0x52 maps to a different organization (e.g., a Philips OID root but DCMTK in the version name), the device manufacturer is surfaced as device_vendor so asset managers can still identify the hardware.

A built-in OID lookup table resolves known vendor roots from 0x52 without requiring network calls to an OID registry. The raw impl_class_uid is printed when verbose is enabled (-v) or when the vendor cannot be identified, as a fallback for manual lookup.

### Native Nmap SSL/TLS Support
The library hooks into Nmap's port.version.service_tunnel property to automatically upgrade connections to SSL/TLS when Nmap's service detection identifies a TLS tunnel. Handles mutual TLS (mTLS) rejection gracefully with an informative hint. Distinguishes dicom vs dicom-tls service names. Includes a heuristic for port 2762 (IANA-registered DICOM TLS) when run without -sV.

### Testing
- Orthanc (dcmtk; PACS), 
- dcm4che-tools (SCP),  
- pynetdicom (SCP), 
- conquest,
- Orthanc with DICOM TLS (stunnel)

## dicom-enum

`dicom-enum.nse` proposes ~28 curated presentation contexts (Verification, the major Storage SOP classes, Modality Worklist FIND, Patient/Study Root Q/R, Storage Commitment, MPPS, and Print) in a single A-ASSOCIATE request and parses the per-PC result map returned in the A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2). Each PC is reported as `accepted`, `user-rejection`, `no-reason`, `abstract-syntax-not-supported`, or `transfer-syntaxes-not-supported`. Storage SOP classes propose the full transfer-syntax matrix (Implicit/Explicit VR, Deflate, JPEG Baseline/Lossless, JPEG-LS, JPEG2000 lossless+lossy, RLE, HTJ2K). Accepted abstract syntaxes are mapped to DICOM service classes and an `inferred_device_class` line (PACS/VNA, Modality, RIS gateway, Archive front-end, Print server) is rendered. Output shape mirrors `ssh2-enum-algos`. Categories are `discovery, safe` (not `default`) — same call the maintainers made for `ssh2-enum-algos`.

The library identifies itself with an ITU-T X.667 self-issued OID (`2.25.<UUID>`) and Implementation Version Name `NMAP_NSE_<version>`. It does not impersonate DCMTK, OFFIS, or any registered vendor. After a successful association the script sends an A-RELEASE-RQ for an orderly close so SCPs do not log the scan as an abort; pass `--script-args dicom.no_release` to skip the release.

Capability-only: `dicom-enum` does **not** brute-force AETs. If the target enforces an AET allowlist, run `dicom-brute` first to learn a valid pair, then pass it via `--script-args dicom.called_aet=<X> dicom.calling_aet=<Y>` to either `dicom-ping` or `dicom-enum`.

## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer
