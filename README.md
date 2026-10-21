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

`dicom-enum.nse` proposes a curated set of presentation contexts (Verification, the Storage SOP classes, Modality Worklist FIND, Patient/Study Root Q/R, Storage Commitment, MPPS, UPS, and Print) in **one A-ASSOCIATE request** (two for the `full` probe; see [Safe on production PACS](#safe-on-production-pacs)) and parses the per-PC result map returned in the A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2). Each PC is reported as `accepted`, `user-rejection`, `no-reason`, `abstract-syntax-not-supported`, or `transfer-syntaxes-not-supported`. Accepted abstract syntaxes are mapped to a `services` summary with one line per PS3.4 Service Class (verification, storage, query, retrieve, modality_worklist, storage_commitment, mpps, ups, print). Each line reads `yes` with the negotiated DIMSE operations and the Q/R information models or SOP classes behind them, `no`, or `not probed` at the chosen probe depth. The mapping also yields `service_classes`, imaging `modalities`, the flat DIMSE `service_commands` list (C-ECHO/C-STORE/C-FIND/C-MOVE/C-GET plus N-CREATE/N-SET/N-ACTION/N-EVENT-REPORT/N-GET/N-DELETE for the workflow and print services), and an `inferred_device_class` line (PACS/VNA, Modality, RIS gateway, Archive front-end, Print server). Output shape mirrors `ssh2-enum-algos`. Categories are `discovery, safe` (not `default`) — same call the maintainers made for `ssh2-enum-algos`.

This script is the merge of two independent efforts (`dicom-enum` + Paulino Calderon's `dicom-info`), keeping the single-association engine and this repo's non-impersonating library while folding in the richer SOP catalogue, DICOM-over-TLS certificate inspection, and the security assessment from `dicom-info`.

### Ubiquity (old and new devices)

Every presentation context is proposed with **Implicit VR Little Endian** — the one transfer syntax every conformant SCP must support (PS3.5 §10.1) — so even the oldest modality negotiates at least one context. The breadth/PDU-size trade-off is controlled by `--script-args dicom-enum.probe`:

| Depth | SOP classes | Storage transfer syntaxes | A-ASSOCIATE-RQ | Use for |
|-------|-------------|---------------------------|----------------|---------|
| `basic` | core | Implicit + Explicit VR only | ~3 KB | fragile/embedded legacy devices |
| `standard` *(default)* | core | commonly-negotiated set (Implicit/Explicit, Deflate, JPEG Baseline/Lossless, JPEG2000 lossless+lossy, RLE) | ~7 KB | everyday scanning |
| `full` | core **+ long tail** (Multi-frame SC, RT, extended SR, UPS, ophthalmic, waveform/ECG, segmentation, parametric map, whole-slide, ...) | the complete matrix incl. JPEG-LS, Explicit VR BE, HTJ2K | ~21 KB, split into two sequential associations (~16 KB + ~5 KB) | exhaustive codec/SOP fingerprinting of modern devices |

The output's `probe` line records the depth used, e.g. `probe: standard (36 presentation contexts proposed, 1 association)`. A `not probed` service, or a difference between two scans of the same host, can then be traced to a probe-depth mismatch.

### Transport & security

Transport adapts to Nmap's own `-sV` SSL/TLS detection, or is forced with `--script-args dicom.tls=true|false`. On a TLS association the peer certificate (subject, issuer, validity, key strength, signature algorithm) is reported, and a `security` block flags findings derived **purely from the single association** — no DIMSE commands or patient data are ever sent: unauthenticated (no AE-title allowlist) access, Query/Retrieve C-FIND/C-MOVE/C-GET exfiltration surface, unauthenticated C-STORE surface, plaintext PHI, a weak or self-signed TLS certificate, and absent mutual TLS (IHE ATNA node authentication).

The library identifies itself with an ITU-T X.667 self-issued OID (`2.25.<UUID>`) and Implementation Version Name `NMAP_NSE`. It does not impersonate DCMTK, OFFIS, or any registered vendor. After a successful association the script sends an A-RELEASE-RQ for an orderly close so SCPs do not log the scan as an abort; pass `--script-args dicom.no_release` to close with A-ABORT instead.

### Safe on production PACS

A PACS's association pool (often 10–50 slots) is shared with modalities and workstations, so the library (and therefore `dicom-ping`, `dicom-enum` and `dicom-brute`) keeps its footprint to one slot per host:

- **One association per host at a time.** Associations to a host are serialized across every DICOM script in the run (an `nmap.mutex` keyed on the host IP), so probing several DICOM ports on one PACS, or running `dicom-ping` and `dicom-enum` together, never opens parallel associations. This also serializes `dicom-brute`'s guesses against a host.
- **Back off when the SCP is busy.** An A-ASSOCIATE-RJ with *temporary-congestion* or *local-limit-exceeded* is retried with exponential backoff (`dicom.retries`, default 2; `dicom.backoff_ms`, default 2000). The host lock is held through the backoff, so the wait is real quiet time on the wire. If the SCP stays busy, both scripts report "SCP busy" rather than misreading it as an AE-title check.
- **Bounded A-ASSOCIATE-RQ size.** PS3.8 allows 128 presentation contexts per request, but some older DCMTK builds, GE and embedded modality stacks reject much smaller requests. Larger proposals are split across sequential associations of at most `dicom.max_pcs` contexts (default 64) and `dicom.max_rq_bytes` bytes (default 16384). Each follow-up association also proposes Verification, because SCPs such as pynetdicom abort a request in which no context is acceptable. If a follow-up association fails, the remaining ones are skipped and `dicom-enum` reports `warning: results are partial`.
- **A-ABORT on every error path.** Once the A-ASSOCIATE-RQ is out, a timeout, an unexpected PDU, a missing A-RELEASE-RP, or a Lua error mid-association sends A-ABORT before the socket closes, so the SCP frees the slot immediately instead of waiting out its ARTIM/idle timer. A-ASSOCIATE-RJ and A-ABORT from the SCP are the exceptions, because the SCP has already ended the association.

Capability-only: `dicom-enum` does **not** brute-force AETs or send DIMSE commands. If the target enforces an AET allowlist, run `dicom-brute` first to learn a valid pair, then pass it via `--script-args dicom.called_aet=<X> dicom.calling_aet=<Y>` to either `dicom-ping` or `dicom-enum`.

## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer
