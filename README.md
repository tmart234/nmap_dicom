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

## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer
