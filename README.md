# nmap_dicom
 nmap PR work for dicom

## Overview
This pull request enhances Nmap's DICOM scanning capabilities by adding vendor detection, version identification
As a fallback mechinism, we output UID root for lookup in a public OID registry (ex: https://oid-base.com/) when vendor is missing. We also output full UID if version extraction was unsucessful (version is encoded sometimes)


This repo tests the following DICOM software in GitHub 
## DICOM Ping script
In the A-ASSOCIATE-AC PDU, the reliable “who/what” identifiers are:
- Implementation Class UID (User Information item, type 0x52) → vendor identity
- Implementation Version Name (User Information item, type 0x55, optional) → implementation version string
### Testing
- Orthanc (dcmtk; PACS), 
- dcm4che-tools (SCP),  
- pynetdicom (SCP), 
- conquest,
- rsdicom
## DICOM Web script
Detect DICOM-related HTTP endpoints
### Testing
- orthanc
- ohif viewer