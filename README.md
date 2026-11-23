# nmap_dicom
PR work for nmap dicom

## Upstream rebase (Nmap 7.992+)

Nmap 7.992 shipped Paulino Calderon's rewritten `nselib/dicom.lua` (a full
DIMSE toolkit) and eight new DICOM scripts (`dicom-info`, `dicom-cfind-ls`,
`dicom-cmove`, `dicom-get`, `dicom-store-fuzzer`, `dicom-store-inject`,
`dicom-slowloris`, `dicom-web-enum`). For the release this repo is **rebased
onto that `dicom.lua`** rather than replacing it: the upstream file is taken
verbatim as the base, and our negotiation engine (`associate_extended` and its
PACS-safety machinery), implementation identification (`resolve_vendor_info`),
and private-tag helpers (`parse_tag_spec`, `extract_private_tags`) are added
cleanly on top. Nothing upstream is removed, so all shipped scripts keep
running unchanged against the merged library.

Rather than introducing a duplicate capability enumerator alongside Nmap's
shipped `dicom-info.nse`, this repo **revises `dicom-info.nse` in place** —
replacing its 18+ sequential associations and C-ECHO probe with a
**single-association, zero-DIMSE, PACS-safe** negotiation engine while keeping
full compatibility with `dicom-info.*` script arguments.

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

## dicom-info

`dicom-info.nse` proposes a curated set of presentation contexts (Verification, the Storage SOP classes, Modality Worklist FIND, Patient/Study Root Q/R, Storage Commitment, MPPS, UPS, and Print) in **one A-ASSOCIATE request** (two for the `full` probe; see [Safe on production PACS](#safe-on-production-pacs)) and parses the per-PC result map returned in the A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2). Each PC is reported as `accepted`, `user-rejection`, `no-reason`, `abstract-syntax-not-supported`, or `transfer-syntaxes-not-supported`, with normal output listing accepted contexts (summarized by transfer syntax above 10; `-v` lists all) plus a one-line-per-reason summary count of any `rejected` ones (the full per-context rejection lists are shown at `-d`). Accepted abstract syntaxes are mapped to a `services` summary showing accepted PS3.4 Service Classes with the negotiated DIMSE operations and Q/R information models (`-v` also includes `no` and `not probed` rows, `service_classes`, and `service_commands`). When an SCP enforces an AE-title allowlist only on Query/Retrieve + Modality Worklist (rejecting a combined association while accepting Verification and Storage), `dicom-info` automatically re-probes without Q/R + MWL so the non-Q/R surface is still enumerated and Q/R is reported as `gated`. The mapping also yields imaging `modalities` and an `inferred_device_class` line (PACS/VNA, Modality, RIS gateway, Archive front-end, Print server).

This script upgrades upstream `dicom-info.nse` to the single-association engine while folding in a rich SOP catalogue, DICOM-over-TLS certificate inspection, and a security assessment. Its negotiation engine and identification helpers live in `nselib/dicom.lua` (see [Upstream rebase](#upstream-rebase-nmap-7992)); `dicom-ping` in this repo consumes the same `associate_extended` / `resolve_vendor_info` API.

### Ubiquity (old and new devices)

Every presentation context includes **Implicit VR Little Endian** — the one transfer syntax every conformant SCP must support (PS3.5 §10.1) — so even the oldest modality negotiates at least one context, and fragile legacy SCPs that abort, reset, or reject multi-kilobyte proposals automatically step down to an internal `fragile` profile (36 core SOP classes, Explicit + Implicit VR only) in 4 KB / 16-context batches. The breadth/PDU-size trade-off is controlled by `--script-args dicom-info.probe` (use `--script=+dicom-info` to force against non-standard ports):

| Depth | SOP classes | Storage transfer syntaxes | A-ASSOCIATE-RQ | Use for |
|-------|-------------|---------------------------|----------------|---------|
| `basic` | 1 (`Verification` only) | Implicit + Explicit VR only | ~250 B (1 association) | minimal whisper-quiet fingerprint (matches upstream 7.992 `basic`) |
| `standard` *(default)* | 36 core + 8 single-syntax codec contexts | commonly-negotiated set (Implicit/Explicit, Deflate, JPEG Baseline/Lossless, JPEG2000 lossless+lossy, RLE) | ~7.5 KB (1 association) | everyday scanning + codec enumeration |
| `full` | 81 (36 core **+ 45 long tail**) + 16 single-syntax codec contexts (Multi-frame SC, RT, extended SR, 3D X-Ray/CBCT, spatial registration, UPS, ophthalmic, waveform/ECG/hemodynamic, segmentation, parametric map, whole-slide, legacy retired US/Q-R, ...) | the complete 16-codec matrix incl. JPEG Extended, JPEG-LS (lossless+near-lossless), Explicit VR BE, HTJ2K | ~31 KB, split into two sequential associations (~16 KB + ~15 KB) | exhaustive codec/SOP fingerprinting of modern & legacy devices |

The output's `probe` line records the depth used, e.g. `probe: standard (36 SOP classes + 8 transfer syntaxes proposed, 1 association)`. A `not probed` service, or a difference between two scans of the same host, can then be traced to the depth.

### Transport & security

Transport adapts to Nmap's own `-sV` SSL/TLS detection, or is forced with `--script-args dicom.tls=true|false`. On a TLS association a `security` block flags terse factual findings derived **purely from the single association** (and `-v` includes the full peer certificate details) — no DIMSE commands or patient data are ever sent: unauthenticated (no AE-title restriction) access, Query/Retrieve C-FIND/C-MOVE/C-GET exposure, unauthenticated Storage exposure, plaintext transport, weak/expired or self-signed TLS certificate, and absent mutual TLS.

The library advertises the Implementation Class UID (`1.2.276.0.7230010.3.0.3.6.7`) and Implementation Version Name (`OFFIS_DCMTK_367`) inherited from the upstream Nmap `dicom.lua` it is rebased onto (see [Upstream rebase](#upstream-rebase-nmap-7992)), which the shipped DICOM scripts use for maximum compatibility with SCPs that validate the calling implementation. After a successful association the script sends an A-RELEASE-RQ for an orderly close so SCPs do not log the scan as an abort; pass `--script-args dicom.no_release` to close with A-ABORT instead.

### Safe on production PACS

A PACS's association pool (often 10-50 slots) is shared with modalities and workstations, so the library (and therefore `dicom-ping`, `dicom-info`, and `dicom-cfind-ls`) keeps its footprint to one slot per host:

- **One association per host at a time.** `dicom.with_host_lock` (and `dicom.associate_extended`, which wraps it) serializes associations per host IP via an `nmap.mutex` shared across `dicom-ping`, `dicom-info`, and `dicom-cfind-ls`, so probing several DICOM ports on one PACS or running those scripts together never opens parallel associations. Upstream `dicom-brute` and `dicom-slowloris` continue to use the preserved upstream `dicom.associate()` / `dicom.do_associate()` APIs verbatim for full drop-in compatibility.
- **Back off when the SCP is busy.** An A-ASSOCIATE-RJ with *temporary-congestion* or *local-limit-exceeded* is retried with exponential backoff (`dicom.retries`, default 2; `dicom.backoff_ms`, default 2000). The host lock is held through the backoff, so the wait is real quiet time on the wire. If the SCP stays busy, the scripts report "SCP busy" rather than misreading it as an AE-title check.
- **Bounded A-ASSOCIATE-RQ size.** PS3.8 allows 128 presentation contexts per request, but some older DCMTK builds, GE and embedded modality stacks reject much smaller requests. Larger proposals are split across sequential associations of at most `dicom.max_pcs` contexts (default 64) and `dicom.max_rq_bytes` bytes (default 16384). Each follow-up association also proposes Verification, because SCPs such as pynetdicom abort a request in which no context is acceptable. If a follow-up association fails, the remaining ones are skipped and `dicom-info` reports `warning: results are partial`.
- **A-ABORT on every error path.** Once the A-ASSOCIATE-RQ is out, a timeout, an unexpected PDU, a missing A-RELEASE-RP, or a Lua error mid-association sends A-ABORT before the socket closes, so the SCP frees the slot immediately instead of waiting out its ARTIM/idle timer. A-ASSOCIATE-RJ and A-ABORT from the SCP are the exceptions, because the SCP has already ended the association.

Capability-only: `dicom-info` does **not** brute-force AETs or send DIMSE commands. If the target enforces an AET allowlist, run `dicom-brute` first to learn a valid pair, then pass it via `--script-args dicom.called_aet=<X> dicom.calling_aet=<Y>` to `dicom-ping`, `dicom-info`, or `dicom-cfind-ls`.

## dicom-cfind-ls

`dicom-cfind-ls.nse` enumerates studies, series, and instances via DIMSE `C-FIND` (and optionally downloads instances via `C-GET` when `dicom-cfind-ls.save` is set), hardened for production clinical PACS and legacy SCPs:

- **Single reusable association & PACS safety:** Runs under `dicom.with_host_lock`, reuses one association across `PATIENT`/`STUDY`/`SERIES`/`IMAGE` drill-down queries (incrementing `MessageID`, transparently reconnecting once for legacy single-query SCPs), retries busy rejects with exponential backoff, caps `C-CANCEL-RQ` drain, and sends `A-ABORT` on error/timeout instead of leaking slots.
- **PS3.4 Patient Root & automatic fallback:** When `info_model=patient`, queries `PATIENT` level first and supplies `PatientID (0010,0020)` for `STUDY`/`SERIES`/`IMAGE` drill-down; when `info_model` is not pinned and Study Root is rejected, automatically falls back to Patient Root.
- **Legacy & modern dataset parsing:** Handles undefined-length sequences (`0xFFFFFFFF`) in both Implicit VR and Explicit VR Little Endian, supports Explicit VR Big Endian (`1.2.840.10008.1.2.2`), reassembles multi-PDU fragmented DIMSE command/data sets (respecting `max_pdu=0` unlimited), and safely formats binary private tags.
- **Private tag enumeration:** Supports `--script-args dicom-cfind-ls.private_tags=true` and custom `dicom-cfind-ls.tags` specs with Private Creator (`gggg,0010-00FF`) resolution.
- **Safe `C-GET` downloads:** Negotiates SCP/SCU role selection (capped at 127 Storage SOPs per PS3.8) and creates output directories with Nmap's built-in `lfs.mkdir` rather than spawning a shell.

## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer
