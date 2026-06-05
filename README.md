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

`dicom-enum.nse` proposes a set of presentation contexts (Verification, the major Storage SOP classes, Modality Worklist FIND, Patient/Study Root Q/R, Storage Commitment, MPPS, and Print) in one or more A-ASSOCIATE requests and parses the per-PC result map returned in the A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2). Each PC is reported as `accepted`, `user-rejection`, `no-reason`, `abstract-syntax-not-supported`, or `transfer-syntaxes-not-supported`. Storage SOP classes propose the full transfer-syntax matrix (Implicit/Explicit VR, Deflate, JPEG Baseline/Lossless, JPEG-LS, JPEG2000 lossless+lossy, RLE, HTJ2K). Accepted abstract syntaxes are mapped to DICOM service classes and an `inferred_device_class` line (PACS/VNA, Modality, RIS gateway, Archive front-end, Print server) is rendered. Output shape mirrors `ssh2-enum-algos`. Categories are `discovery, safe` (not `default`) — same call the maintainers made for `ssh2-enum-algos`.

### SOP-class coverage (`dicom-enum.sop`)

- `curated` (default) — ~35 of the most common SOP classes in a **single** A-ASSOCIATE request. One round trip, quiet on the wire; the right default for a clinical network.
- `full` (alias `all`) — the full PS3.6 registry of standard SOP classes (~165). Because an A-ASSOCIATE-RQ caps at **128** presentation contexts (PS3.8 §9.3.2.2 — one-octet odd PC IDs → 1..255 → 128) **and** at the PDU size, the full list is automatically split into several A-ASSOCIATE requests ("batches") and the accepted buckets are merged. This is *enumeration of a published list*, not brute force: there is no "list everything" command in DICOM, so coverage equals the proposed list, and private/vendor SOP UIDs cannot be discovered this way.

There is deliberately no one-PC-per-association mode — the per-PC result map already gives the same accept/reject granularity inside a batched request, so single-context probing only multiplies associations (slow, and noisy enough to trip association/abort-rate alarms). For a stack that cannot handle a multi-context request, shrink the batch with `dicom-enum.max_pcs` (e.g. `=1`) instead.

A whole-association **A-ASSOCIATE-RJ** (AET allowlist, application-context, protocol-version, congestion) happens *before* any presentation context is evaluated. If nothing at all associates it is reported once with an actionable hint; clear the AET gate first (see `dicom-brute` below), then re-run with `dicom-enum.sop=full` to enumerate the capability surface.

```
nmap -p 4242 --script dicom-enum --script-args dicom-enum.sop=full <target>
```

### Adaptive tier isolation (non-conformant devices)

Some real devices negotiate badly:

- They **drop or abort the entire association** merely because a Query/Retrieve abstract syntax is present in the request — even though PS3.8 §9.3.3.2 says they must reject the offending *presentation context*, not the association. (Such a box is typically a Q/R *SCU* — it queries other nodes and has no inbound Q/R role.)
- They enforce the **AET allowlist on Storage/operations but not on Verification (C-ECHO)**, so a plain ping looks "open" while real operations are gated.

A naive single-association scan just "fails" against these. So when the fast combined pass loses a batch wholesale, `dicom-enum` re-probes the failed contexts **one tier at a time** — Verification, then core (Storage/Worklist/MPPS/StgCmt/Print), then Query/Retrieve — so a hostile tier can't hide the capabilities of the others. The offending behavior is reported as a `quirk_*` line (a strong device fingerprint in its own right), e.g.:

```
| dicom-enum:
|   association: accepted (max_pdu=16384)
|   scan: curated coverage: 36 SOP classes across 4 association(s); isolated failing groups by tier
|   quirk_query_retrieve: Drops/aborts the whole association when a Query/Retrieve SOP class is proposed ...
|   quirk_operations: Rejects associations proposing non-Verification operations while accepting Verification — AET/allowlist enforcement likely applies to Storage/operations but not to C-ECHO.
|   service_classes:
|     Storage
|_    Verification
```

Pass `dicom-enum.isolate` to skip the combined pass and probe per tier from the start (for a device already known to be hostile), or `dicom-enum.max_pcs=1` for a stack that cannot handle multi-context requests.

The library identifies itself with an ITU-T X.667 self-issued OID (`2.25.<UUID>`) and Implementation Version Name `NMAP_NSE`. It does not impersonate DCMTK, OFFIS, or any registered vendor. After a successful association the script sends an A-RELEASE-RQ for an orderly close so SCPs do not log the scan as an abort; pass `--script-args dicom.no_release` to skip the release.

Capability-only: `dicom-enum` does **not** brute-force AETs. If the target enforces an AET allowlist, run `dicom-brute` first to learn a valid pair, then pass it via `--script-args dicom.called_aet=<X> dicom.calling_aet=<Y>` to either `dicom-ping` or `dicom-enum`.

## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer
