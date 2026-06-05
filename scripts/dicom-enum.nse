--[[
Enumerates the SOP classes and transfer syntaxes a DICOM Service Provider
accepts by proposing a set of presentation contexts in one or more
A-ASSOCIATE requests and parsing the per-PC result map returned in each
A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2).

Each presentation context is reported as one of:
  accepted (0), user-rejection (1), no-reason (2),
  abstract-syntax-not-supported (3), transfer-syntaxes-not-supported (4)

Only the "accepted" bucket is rendered in normal script output — that is
the SCP's positive capability surface. The other four buckets are emitted
at debug level only (-d), since "everything we proposed that this SCP
doesn't serve" is useful for triage but noise in default output.

This is a capability fingerprint: it identifies which Storage SOP classes
the SCP serves (CT/MR/US/CR/DX/Mammo/PET/NM/XA/XRF/Endoscopy/...), whether
it supports Modality Worklist FIND, Patient/Study Root Query/Retrieve,
Storage Commitment, MPPS, and Print Management, and which transfer
syntaxes it negotiates.

SOP-class coverage (dicom-enum.sop):
  curated (default) - ~35 of the most common SOP classes, sent in a single
                      A-ASSOCIATE request. One round trip, quiet on the
                      wire — the right default for a clinical network.
  full              - the full PS3.6 registry of standard SOP classes
                      (~165). Because an A-ASSOCIATE-RQ caps at 128
                      presentation contexts (PS3.8 §9.3.2.2, one-octet odd
                      PC IDs -> 1..255 -> 128) and at the PDU size, the full
                      list is automatically split into several A-ASSOCIATE
                      requests ("batches") and the accepted buckets are
                      merged. This is enumeration of a published list, NOT
                      brute force — there is no "list everything" command in
                      DICOM, so coverage equals the proposed list. Private /
                      vendor SOP UIDs cannot be discovered this way.

There is deliberately no one-PC-per-association mode: the per-PC result map
already gives the same accept/reject granularity inside a batched request,
so single-context probing only multiplies associations (slow, and noisy
enough to trip association/abort-rate alarms in clinical nets). For a stack
that cannot handle a multi-context request, shrink the batch with
dicom-enum.max_pcs instead.

Adaptive tier isolation: some non-conformant devices drop or abort the
*entire* association merely because a Query/Retrieve abstract syntax is
present in the request (PS3.8 §9.3.3.2 says they should reject the offending
presentation context, not the association), and some enforce the AET
allowlist on Storage/operations while leaving Verification open. A naive
single-association scan just "fails" against these. So when the fast
combined pass loses a batch wholesale, the script re-probes the failed
contexts one tier at a time — Verification, then core (Storage/Worklist/
MPPS/StgCmt/Print), then Query/Retrieve — so a hostile tier can't hide the
capabilities of the others. The offending behavior is then reported as a
quirk_* line, which is itself a strong device fingerprint. Pass
dicom-enum.isolate to go straight to tiered probing for a known-hostile
device.

From the accepted SOP classes the script also derives:
  modalities         - the imaging modalities implied by accepted Storage
                       SOP classes (CT, MRI, Ultrasound, Mammography,
                       X-Ray, X-Ray Angiography, Fluoroscopy, PET, PET-CT,
                       Nuclear Medicine, Endoscopy, ...). PET-CT is
                       reported when both PET and CT are accepted.
  service_commands   - the DIMSE commands implied by the accepted SOP
                       classes: C-ECHO (Verification), C-STORE (Storage),
                       C-FIND (Q/R FIND or Modality Worklist FIND),
                       C-MOVE (Q/R MOVE), C-GET (Q/R GET).
  inferred_device_class - PACS/VNA, Modality, RIS gateway, Archive
                       front-end, or Print server. This taxonomy is a
                       practitioner consensus, not a normative DICOM
                       concept; treat it as a fingerprint, not a
                       classification.

This script does NOT brute-force Application Entity Titles. If the target
PACS enforces an AET allowlist, the association is rejected before any
PC results come back — use dicom-brute first to discover a valid AET pair,
then pass it via dicom.called_aet / dicom.calling_aet here.

Modeled on ssh2-enum-algos: discovery + safe categories, NOT default.
]]

---
-- @usage nmap -p 4242 --script dicom-enum <target>
-- @usage nmap -sV -p 4242 --script dicom-enum <target>
-- @usage nmap -p 11112 --script dicom-enum --script-args dicom.called_aet=ORTHANC <target>
-- @usage nmap -p 4242 --script dicom-enum --script-args dicom-enum.sop=full <target>
-- @usage nmap --script dicom-enum --script-args dicom-enum.ports=11114,11115 <target>
--
-- @args dicom.called_aet     Called AET. Default: ANY-SCP
-- @args dicom.calling_aet    Calling AET. Default: ECHOSCU
-- @args dicom.timeout_ms     Socket timeout in ms. Default: 3000
-- @args dicom.no_release     If set, the script omits A-RELEASE-RQ and lets
--                            the SCP see an aborted association. Default:
--                            unset (release is sent).
-- @args dicom-enum.sop       SOP-class coverage: "curated" (default, ~35
--                            common classes in one association) or "full"
--                            (the full PS3.6 registry, ~165 classes, split
--                            into batched associations). "all" is an alias
--                            for "full".
-- @args dicom-enum.max_pcs   Maximum presentation contexts per A-ASSOCIATE
--                            request. Default: 128 (the PS3.8 protocol
--                            ceiling). Lower it (e.g. =1) for a stack that
--                            cannot handle multi-context requests.
-- @args dicom-enum.isolate   If set, skip the fast combined pass and probe
--                            each tier (Verification / core / Query-Retrieve)
--                            in its own association from the start. Use it for
--                            a device already known to drop or abort the whole
--                            association when a Q/R context is present, to
--                            avoid the wasted failing combined association.
-- @args dicom-enum.ports     Optional comma-separated list of ports to
--                            probe (e.g. "104,11112,2761,2762,4242").
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-enum:
-- |   association: accepted (max_pdu=16384, vendor=Orthanc 1.11.0)
-- |   service_classes:
-- |     QR-Patient-Root
-- |     QR-Study-Root
-- |     Storage
-- |     Verification
-- |   service_commands:
-- |     C-ECHO
-- |     C-FIND
-- |     C-GET
-- |     C-MOVE
-- |     C-STORE
-- |   modalities:
-- |     CT
-- |     MRI
-- |     Mammography
-- |     PET
-- |     PET-CT
-- |     Ultrasound
-- |     X-Ray (DX)
-- |   inferred_device_class: Archive front-end
-- |   results:
-- |     accepted:
-- |       count: 15
-- |       items:
-- |         Verification - Implicit VR Little Endian
-- |         CT Image Storage - Explicit VR Little Endian
-- |_        MR Image Storage - JPEG 2000 Image Compression (Lossless Only)
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-enum:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Association rejected: rejected-permanent / DICOM-UL-service-user / called-AE-title-not-recognized
-- |_  hint: Called-AET not recognized — try dicom.called_aet=<AET>
--
-- @xmloutput
-- <elem key="association">accepted (max_pdu=16384, vendor=Orthanc 1.11.0)</elem>
-- <table key="service_classes">
--   <elem>QR-Patient-Root</elem>
--   <elem>QR-Study-Root</elem>
--   <elem>Storage</elem>
--   <elem>Verification</elem>
-- </table>
-- <table key="service_commands">
--   <elem>C-ECHO</elem>
--   <elem>C-FIND</elem>
--   <elem>C-GET</elem>
--   <elem>C-MOVE</elem>
--   <elem>C-STORE</elem>
-- </table>
-- <table key="modalities">
--   <elem>CT</elem>
--   <elem>MRI</elem>
--   <elem>PET</elem>
--   <elem>PET-CT</elem>
-- </table>
-- <elem key="inferred_device_class">Archive front-end</elem>
-- <table key="results">
--   <table key="accepted">
--     <elem key="count">15</elem>
--     <table key="items">
--       <elem>Verification - Implicit VR Little Endian</elem>
--     </table>
--   </table>
-- </table>
---

author     = "Tyler M <tmart234()gmail.com>"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local dicom     = require "dicom"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local table     = require "table"
local string    = require "string"

-- ---------- Transfer syntaxes ----------
-- Abstract syntax UIDs are taken from PS3.4 (Storage / Worklist / Q-R) and
-- PS3.6 (registry of UIDs).

local TS_I       = "1.2.840.10008.1.2"        -- Implicit VR LE
local TS_E       = "1.2.840.10008.1.2.1"      -- Explicit VR LE
local TS_EBE     = "1.2.840.10008.1.2.2"      -- Explicit VR Big Endian
local TS_DEFLATE = "1.2.840.10008.1.2.1.99"   -- Deflated Explicit VR LE
local TS_JPEG_BL = "1.2.840.10008.1.2.4.50"   -- JPEG Baseline (Process 1)
local TS_JPEG_LL = "1.2.840.10008.1.2.4.70"   -- JPEG Lossless
local TS_JLS_LL  = "1.2.840.10008.1.2.4.80"   -- JPEG-LS Lossless
local TS_J2K_LL  = "1.2.840.10008.1.2.4.90"   -- JPEG 2000 (Lossless Only)
local TS_J2K     = "1.2.840.10008.1.2.4.91"   -- JPEG 2000 (Lossy)
local TS_RLE     = "1.2.840.10008.1.2.5"      -- RLE Lossless
local TS_HTJ2K_L = "1.2.840.10008.1.2.4.201"  -- HTJ2K Lossless (Sup235)
local TS_HTJ2K_R = "1.2.840.10008.1.2.4.202"  -- HTJ2K Lossless RPCL
local TS_HTJ2K   = "1.2.840.10008.1.2.4.203"  -- HTJ2K (Lossy)

-- Storage SOP classes accept the full transfer-syntax matrix.
local STORAGE_TS = {
  TS_I, TS_E, TS_EBE, TS_DEFLATE,
  TS_JPEG_BL, TS_JPEG_LL, TS_JLS_LL,
  TS_J2K_LL, TS_J2K, TS_RLE,
  TS_HTJ2K_L, TS_HTJ2K_R, TS_HTJ2K,
}

-- Non-storage classes (Verification, Q/R, MWL, MPPS, StgCmt, Print) do not
-- benefit from compressed transfer syntaxes; keep the proposal minimal.
local CMD_TS = {TS_I, TS_E}

-- ---------- Curated Presentation Context list (default) ----------
-- The ~35 most common SOP classes, sized to fit a single A-ASSOCIATE.

local CURATED_PC_LIST = {
  -- Verification
  {name = "Verification",                                uid = "1.2.840.10008.1.1",                   ts = CMD_TS},

  -- Storage SOP classes
  {name = "CT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.2",           ts = STORAGE_TS},
  {name = "Enhanced CT Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.2.1",         ts = STORAGE_TS},
  {name = "MR Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.4",           ts = STORAGE_TS},
  {name = "Enhanced MR Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.4.1",         ts = STORAGE_TS},
  {name = "Ultrasound Image Storage",                    uid = "1.2.840.10008.5.1.4.1.1.6.1",         ts = STORAGE_TS},
  {name = "Ultrasound Multi-frame Image Storage",        uid = "1.2.840.10008.5.1.4.1.1.3.1",         ts = STORAGE_TS},
  {name = "Computed Radiography Image Storage",          uid = "1.2.840.10008.5.1.4.1.1.1",           ts = STORAGE_TS},
  {name = "Digital X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.1",      ts = STORAGE_TS},
  {name = "Digital X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.1.1",    ts = STORAGE_TS},
  {name = "Digital Mammography X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.2",   ts = STORAGE_TS},
  {name = "Digital Mammography X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.2.1", ts = STORAGE_TS},
  {name = "X-Ray Angiographic Image Storage",            uid = "1.2.840.10008.5.1.4.1.1.12.1",        ts = STORAGE_TS},
  {name = "Enhanced X-Ray Angiographic Image Storage",   uid = "1.2.840.10008.5.1.4.1.1.12.1.1",      ts = STORAGE_TS},
  {name = "X-Ray Radiofluoroscopic Image Storage",       uid = "1.2.840.10008.5.1.4.1.1.12.2",        ts = STORAGE_TS},
  {name = "Enhanced X-Ray Radiofluoroscopic Image Storage", uid = "1.2.840.10008.5.1.4.1.1.12.2.1",   ts = STORAGE_TS},
  {name = "Nuclear Medicine Image Storage",              uid = "1.2.840.10008.5.1.4.1.1.20",          ts = STORAGE_TS},
  {name = "Positron Emission Tomography Image Storage",  uid = "1.2.840.10008.5.1.4.1.1.128",         ts = STORAGE_TS},
  {name = "Enhanced PET Image Storage",                  uid = "1.2.840.10008.5.1.4.1.1.130",         ts = STORAGE_TS},
  {name = "VL Endoscopic Image Storage",                 uid = "1.2.840.10008.5.1.4.1.1.77.1.1",      ts = STORAGE_TS},
  {name = "Video Endoscopic Image Storage",              uid = "1.2.840.10008.5.1.4.1.1.77.1.1.1",    ts = STORAGE_TS},
  {name = "Secondary Capture Image Storage",             uid = "1.2.840.10008.5.1.4.1.1.7",           ts = STORAGE_TS},
  {name = "Encapsulated PDF Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.1",       ts = STORAGE_TS},
  {name = "Basic Text SR Storage",                       uid = "1.2.840.10008.5.1.4.1.1.88.11",       ts = STORAGE_TS},
  {name = "Comprehensive SR Storage",                    uid = "1.2.840.10008.5.1.4.1.1.88.33",       ts = STORAGE_TS},
  {name = "Grayscale Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.1",      ts = STORAGE_TS},

  -- Worklist + Query/Retrieve
  {name = "Modality Worklist Information Model - FIND",  uid = "1.2.840.10008.5.1.4.31",              ts = CMD_TS},
  {name = "Patient Root Query/Retrieve - FIND",          uid = "1.2.840.10008.5.1.4.1.2.1.1",         ts = CMD_TS},
  {name = "Patient Root Query/Retrieve - MOVE",          uid = "1.2.840.10008.5.1.4.1.2.1.2",         ts = CMD_TS},
  {name = "Patient Root Query/Retrieve - GET",           uid = "1.2.840.10008.5.1.4.1.2.1.3",         ts = CMD_TS},
  {name = "Study Root Query/Retrieve - FIND",            uid = "1.2.840.10008.5.1.4.1.2.2.1",         ts = CMD_TS},
  {name = "Study Root Query/Retrieve - MOVE",            uid = "1.2.840.10008.5.1.4.1.2.2.2",         ts = CMD_TS},
  {name = "Study Root Query/Retrieve - GET",             uid = "1.2.840.10008.5.1.4.1.2.2.3",         ts = CMD_TS},

  -- Workflow
  {name = "Storage Commitment Push Model",               uid = "1.2.840.10008.1.20.1",                ts = CMD_TS},
  {name = "Modality Performed Procedure Step",           uid = "1.2.840.10008.3.1.2.3.3",             ts = CMD_TS},

  -- Print
  {name = "Basic Grayscale Print Management Meta",       uid = "1.2.840.10008.5.1.1.9",               ts = CMD_TS},
}

-- ---------- Additional Presentation Contexts for "full" coverage ----------
-- Everything else from the PS3.6 registry not already in CURATED_PC_LIST.
-- Concatenated after the curated list to form the full proposal. No UID
-- appears in both lists.

local EXTRA_PC_LIST = {
  -- Additional Storage SOP classes
  {name = "Digital Intra-oral X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.3",   ts = STORAGE_TS},
  {name = "Digital Intra-oral X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.3.1", ts = STORAGE_TS},
  {name = "MR Spectroscopy Storage",                     uid = "1.2.840.10008.5.1.4.1.1.4.2",         ts = STORAGE_TS},
  {name = "Enhanced MR Color Image Storage",             uid = "1.2.840.10008.5.1.4.1.1.4.3",         ts = STORAGE_TS},
  {name = "Enhanced US Volume Storage",                  uid = "1.2.840.10008.5.1.4.1.1.6.2",         ts = STORAGE_TS},
  {name = "Multi-frame Single Bit Secondary Capture Image Storage",    uid = "1.2.840.10008.5.1.4.1.1.7.1",   ts = STORAGE_TS},
  {name = "Multi-frame Grayscale Byte Secondary Capture Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.2",  ts = STORAGE_TS},
  {name = "Multi-frame Grayscale Word Secondary Capture Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.3",  ts = STORAGE_TS},
  {name = "Multi-frame True Color Secondary Capture Image Storage",    uid = "1.2.840.10008.5.1.4.1.1.7.4",   ts = STORAGE_TS},
  {name = "12-lead ECG Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.1.1",       ts = STORAGE_TS},
  {name = "General ECG Waveform Storage",                 uid = "1.2.840.10008.5.1.4.1.1.9.1.2",       ts = STORAGE_TS},
  {name = "Ambulatory ECG Waveform Storage",             uid = "1.2.840.10008.5.1.4.1.1.9.1.3",       ts = STORAGE_TS},
  {name = "Hemodynamic Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.2.1",       ts = STORAGE_TS},
  {name = "Cardiac Electrophysiology Waveform Storage",  uid = "1.2.840.10008.5.1.4.1.1.9.3.1",       ts = STORAGE_TS},
  {name = "Basic Voice Audio Waveform Storage",          uid = "1.2.840.10008.5.1.4.1.1.9.4.1",       ts = STORAGE_TS},
  {name = "General Audio Waveform Storage",              uid = "1.2.840.10008.5.1.4.1.1.9.4.2",       ts = STORAGE_TS},
  {name = "Arterial Pulse Waveform Storage",             uid = "1.2.840.10008.5.1.4.1.1.9.5.1",       ts = STORAGE_TS},
  {name = "Respiratory Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.6.1",       ts = STORAGE_TS},
  {name = "Color Softcopy Presentation State Storage",   uid = "1.2.840.10008.5.1.4.1.1.11.2",        ts = STORAGE_TS},
  {name = "Pseudo-Color Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.3",   ts = STORAGE_TS},
  {name = "Blending Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.4",       ts = STORAGE_TS},
  {name = "XA/XRF Grayscale Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.5", ts = STORAGE_TS},
  {name = "X-Ray 3D Angiographic Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.13.1.1",      ts = STORAGE_TS},
  {name = "X-Ray 3D Craniofacial Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.13.1.2",      ts = STORAGE_TS},
  {name = "Breast Tomosynthesis Image Storage",          uid = "1.2.840.10008.5.1.4.1.1.13.1.3",      ts = STORAGE_TS},
  {name = "Intravascular OCT Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.14.1", ts = STORAGE_TS},
  {name = "Intravascular OCT Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.14.2", ts = STORAGE_TS},
  {name = "Raw Data Storage",                            uid = "1.2.840.10008.5.1.4.1.1.66",          ts = STORAGE_TS},
  {name = "Spatial Registration Storage",                uid = "1.2.840.10008.5.1.4.1.1.66.1",        ts = STORAGE_TS},
  {name = "Spatial Fiducials Storage",                   uid = "1.2.840.10008.5.1.4.1.1.66.2",        ts = STORAGE_TS},
  {name = "Deformable Spatial Registration Storage",     uid = "1.2.840.10008.5.1.4.1.1.66.3",        ts = STORAGE_TS},
  {name = "Segmentation Storage",                        uid = "1.2.840.10008.5.1.4.1.1.66.4",        ts = STORAGE_TS},
  {name = "Surface Segmentation Storage",                uid = "1.2.840.10008.5.1.4.1.1.66.5",        ts = STORAGE_TS},
  {name = "Real World Value Mapping Storage",            uid = "1.2.840.10008.5.1.4.1.1.67",          ts = STORAGE_TS},
  {name = "Surface Scan Mesh Storage",                   uid = "1.2.840.10008.5.1.4.1.1.68.1",        ts = STORAGE_TS},
  {name = "Surface Scan Point Cloud Storage",            uid = "1.2.840.10008.5.1.4.1.1.68.2",        ts = STORAGE_TS},
  {name = "VL Microscopic Image Storage",                uid = "1.2.840.10008.5.1.4.1.1.77.1.2",      ts = STORAGE_TS},
  {name = "Video Microscopic Image Storage",             uid = "1.2.840.10008.5.1.4.1.1.77.1.2.1",    ts = STORAGE_TS},
  {name = "VL Slide-Coordinates Microscopic Image Storage", uid = "1.2.840.10008.5.1.4.1.1.77.1.3",   ts = STORAGE_TS},
  {name = "VL Photographic Image Storage",               uid = "1.2.840.10008.5.1.4.1.1.77.1.4",      ts = STORAGE_TS},
  {name = "Video Photographic Image Storage",            uid = "1.2.840.10008.5.1.4.1.1.77.1.4.1",    ts = STORAGE_TS},
  {name = "Ophthalmic Photography 8 Bit Image Storage",  uid = "1.2.840.10008.5.1.4.1.1.77.1.5.1",    ts = STORAGE_TS},
  {name = "Ophthalmic Photography 16 Bit Image Storage", uid = "1.2.840.10008.5.1.4.1.1.77.1.5.2",    ts = STORAGE_TS},
  {name = "Stereometric Relationship Storage",           uid = "1.2.840.10008.5.1.4.1.1.77.1.5.3",    ts = STORAGE_TS},
  {name = "Ophthalmic Tomography Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.77.1.5.4",    ts = STORAGE_TS},
  {name = "VL Whole Slide Microscopy Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.77.1.6",      ts = STORAGE_TS},
  {name = "Lensometry Measurements Storage",             uid = "1.2.840.10008.5.1.4.1.1.78.1",        ts = STORAGE_TS},
  {name = "Autorefraction Measurements Storage",         uid = "1.2.840.10008.5.1.4.1.1.78.2",        ts = STORAGE_TS},
  {name = "Keratometry Measurements Storage",            uid = "1.2.840.10008.5.1.4.1.1.78.3",        ts = STORAGE_TS},
  {name = "Subjective Refraction Measurements Storage",  uid = "1.2.840.10008.5.1.4.1.1.78.4",        ts = STORAGE_TS},
  {name = "Visual Acuity Measurements Storage",          uid = "1.2.840.10008.5.1.4.1.1.78.5",        ts = STORAGE_TS},
  {name = "Spectacle Prescription Report Storage",       uid = "1.2.840.10008.5.1.4.1.1.78.6",        ts = STORAGE_TS},
  {name = "Ophthalmic Axial Measurements Storage",       uid = "1.2.840.10008.5.1.4.1.1.78.7",        ts = STORAGE_TS},
  {name = "Intraocular Lens Calculations Storage",       uid = "1.2.840.10008.5.1.4.1.1.78.8",        ts = STORAGE_TS},
  {name = "Macular Grid Thickness and Volume Report Storage", uid = "1.2.840.10008.5.1.4.1.1.79.1",   ts = STORAGE_TS},
  {name = "Ophthalmic Visual Field Static Perimetry Measurements Storage", uid = "1.2.840.10008.5.1.4.1.1.80.1", ts = STORAGE_TS},
  {name = "Ophthalmic Thickness Map Storage",            uid = "1.2.840.10008.5.1.4.1.1.81.1",        ts = STORAGE_TS},
  {name = "Corneal Topography Map Storage",              uid = "1.2.840.10008.5.1.4.1.1.82.1",        ts = STORAGE_TS},
  {name = "Enhanced SR Storage",                         uid = "1.2.840.10008.5.1.4.1.1.88.22",       ts = STORAGE_TS},
  {name = "Comprehensive 3D SR Storage",                 uid = "1.2.840.10008.5.1.4.1.1.88.34",       ts = STORAGE_TS},
  {name = "Procedure Log Storage",                       uid = "1.2.840.10008.5.1.4.1.1.88.40",       ts = STORAGE_TS},
  {name = "Mammography CAD SR Storage",                  uid = "1.2.840.10008.5.1.4.1.1.88.50",       ts = STORAGE_TS},
  {name = "Key Object Selection Document Storage",       uid = "1.2.840.10008.5.1.4.1.1.88.59",       ts = STORAGE_TS},
  {name = "Chest CAD SR Storage",                        uid = "1.2.840.10008.5.1.4.1.1.88.65",       ts = STORAGE_TS},
  {name = "X-Ray Radiation Dose SR Storage",             uid = "1.2.840.10008.5.1.4.1.1.88.67",       ts = STORAGE_TS},
  {name = "Colon CAD SR Storage",                        uid = "1.2.840.10008.5.1.4.1.1.88.69",       ts = STORAGE_TS},
  {name = "Implantation Plan SR Document Storage",       uid = "1.2.840.10008.5.1.4.1.1.88.70",       ts = STORAGE_TS},
  {name = "Encapsulated CDA Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.2",       ts = STORAGE_TS},
  {name = "Basic Structured Display Storage",            uid = "1.2.840.10008.5.1.4.1.1.131",         ts = STORAGE_TS},
  {name = "RT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.481.1",       ts = STORAGE_TS},
  {name = "RT Dose Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.2",       ts = STORAGE_TS},
  {name = "RT Structure Set Storage",                    uid = "1.2.840.10008.5.1.4.1.1.481.3",       ts = STORAGE_TS},
  {name = "RT Beams Treatment Record Storage",           uid = "1.2.840.10008.5.1.4.1.1.481.4",       ts = STORAGE_TS},
  {name = "RT Plan Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.5",       ts = STORAGE_TS},
  {name = "RT Brachy Treatment Record Storage",          uid = "1.2.840.10008.5.1.4.1.1.481.6",       ts = STORAGE_TS},
  {name = "RT Treatment Summary Record Storage",         uid = "1.2.840.10008.5.1.4.1.1.481.7",       ts = STORAGE_TS},
  {name = "Hanging Protocol Storage",                    uid = "1.2.840.10008.5.1.4.38.1",            ts = STORAGE_TS},
  {name = "Color Palette Storage",                       uid = "1.2.840.10008.5.1.4.39.1",            ts = STORAGE_TS},
  {name = "Generic Implant Template Storage",            uid = "1.2.840.10008.5.1.4.43.1",            ts = STORAGE_TS},
  {name = "Implant Assembly Template Storage",           uid = "1.2.840.10008.5.1.4.44.1",            ts = STORAGE_TS},
  {name = "Implant Template Group Storage",              uid = "1.2.840.10008.5.1.4.45.1",            ts = STORAGE_TS},

  -- Additional Query/Retrieve
  {name = "Patient/Study Only Query/Retrieve - FIND (Retired)", uid = "1.2.840.10008.5.1.4.1.2.3.1",  ts = CMD_TS},
  {name = "Patient/Study Only Query/Retrieve - MOVE (Retired)", uid = "1.2.840.10008.5.1.4.1.2.3.2",  ts = CMD_TS},
  {name = "Patient/Study Only Query/Retrieve - GET (Retired)",  uid = "1.2.840.10008.5.1.4.1.2.3.3",  ts = CMD_TS},
  {name = "Composite Instance Root Retrieve - MOVE",     uid = "1.2.840.10008.5.1.4.1.2.4.2",         ts = CMD_TS},
  {name = "Composite Instance Root Retrieve - GET",      uid = "1.2.840.10008.5.1.4.1.2.4.3",         ts = CMD_TS},
  {name = "Composite Instance Retrieve Without Bulk Data - GET", uid = "1.2.840.10008.5.1.4.1.2.5.3", ts = CMD_TS},
  {name = "Hanging Protocol Information Model - FIND",    uid = "1.2.840.10008.5.1.4.38.2",            ts = CMD_TS},
  {name = "Hanging Protocol Information Model - MOVE",    uid = "1.2.840.10008.5.1.4.38.3",            ts = CMD_TS},
  {name = "Color Palette Information Model - FIND",       uid = "1.2.840.10008.5.1.4.39.2",            ts = CMD_TS},
  {name = "Color Palette Information Model - MOVE",       uid = "1.2.840.10008.5.1.4.39.3",            ts = CMD_TS},
  {name = "Color Palette Information Model - GET",        uid = "1.2.840.10008.5.1.4.39.4",            ts = CMD_TS},
  {name = "General Relevant Patient Information Query",   uid = "1.2.840.10008.5.1.4.37.1",            ts = CMD_TS},
  {name = "Breast Imaging Relevant Patient Information Query", uid = "1.2.840.10008.5.1.4.37.2",       ts = CMD_TS},
  {name = "Cardiac Relevant Patient Information Query",   uid = "1.2.840.10008.5.1.4.37.3",            ts = CMD_TS},
  {name = "Product Characteristics Query",               uid = "1.2.840.10008.5.1.4.41",              ts = CMD_TS},
  {name = "Substance Approval Query",                    uid = "1.2.840.10008.5.1.4.42",              ts = CMD_TS},
  {name = "Generic Implant Template Information Model - FIND", uid = "1.2.840.10008.5.1.4.43.2",       ts = CMD_TS},
  {name = "Generic Implant Template Information Model - MOVE", uid = "1.2.840.10008.5.1.4.43.3",       ts = CMD_TS},
  {name = "Generic Implant Template Information Model - GET",  uid = "1.2.840.10008.5.1.4.43.4",       ts = CMD_TS},
  {name = "Implant Assembly Template Information Model - FIND", uid = "1.2.840.10008.5.1.4.44.2",      ts = CMD_TS},
  {name = "Implant Assembly Template Information Model - MOVE", uid = "1.2.840.10008.5.1.4.44.3",      ts = CMD_TS},
  {name = "Implant Assembly Template Information Model - GET",  uid = "1.2.840.10008.5.1.4.44.4",      ts = CMD_TS},
  {name = "Implant Template Group Information Model - FIND", uid = "1.2.840.10008.5.1.4.45.2",         ts = CMD_TS},
  {name = "Implant Template Group Information Model - MOVE", uid = "1.2.840.10008.5.1.4.45.3",         ts = CMD_TS},
  {name = "Implant Template Group Information Model - GET",  uid = "1.2.840.10008.5.1.4.45.4",         ts = CMD_TS},

  -- Additional Workflow / Management
  {name = "Procedural Event Logging",                    uid = "1.2.840.10008.1.40",                  ts = CMD_TS},
  {name = "Substance Administration Logging",            uid = "1.2.840.10008.1.42",                  ts = CMD_TS},
  {name = "Modality Performed Procedure Step Retrieve",  uid = "1.2.840.10008.3.1.2.3.4",             ts = CMD_TS},
  {name = "Modality Performed Procedure Step Notification", uid = "1.2.840.10008.3.1.2.3.5",          ts = CMD_TS},
  {name = "Instance Availability Notification",          uid = "1.2.840.10008.5.1.4.33",              ts = CMD_TS},
  {name = "Unified Procedure Step - Push",               uid = "1.2.840.10008.5.1.4.34.6.1",          ts = CMD_TS},
  {name = "Unified Procedure Step - Watch",              uid = "1.2.840.10008.5.1.4.34.6.2",          ts = CMD_TS},
  {name = "Unified Procedure Step - Pull",               uid = "1.2.840.10008.5.1.4.34.6.3",          ts = CMD_TS},
  {name = "Unified Procedure Step - Event",              uid = "1.2.840.10008.5.1.4.34.6.4",          ts = CMD_TS},
  {name = "RT Conventional Machine Verification",        uid = "1.2.840.10008.5.1.4.34.8",            ts = CMD_TS},
  {name = "RT Ion Machine Verification",                 uid = "1.2.840.10008.5.1.4.34.9",            ts = CMD_TS},

  -- Additional Print Management
  {name = "Basic Color Print Management Meta",           uid = "1.2.840.10008.5.1.1.18",              ts = CMD_TS},
  {name = "Basic Film Session SOP Class",                uid = "1.2.840.10008.5.1.1.1",               ts = CMD_TS},
  {name = "Basic Film Box SOP Class",                    uid = "1.2.840.10008.5.1.1.2",               ts = CMD_TS},
  {name = "Basic Grayscale Image Box SOP Class",         uid = "1.2.840.10008.5.1.1.4",               ts = CMD_TS},
  {name = "Basic Color Image Box SOP Class",             uid = "1.2.840.10008.5.1.1.4.1",             ts = CMD_TS},
  {name = "Print Job SOP Class",                         uid = "1.2.840.10008.5.1.1.14",              ts = CMD_TS},
  {name = "Basic Annotation Box SOP Class",              uid = "1.2.840.10008.5.1.1.15",              ts = CMD_TS},
  {name = "Printer SOP Class",                           uid = "1.2.840.10008.5.1.1.16",              ts = CMD_TS},
  {name = "Printer Configuration Retrieval SOP Class",   uid = "1.2.840.10008.5.1.1.16.376",          ts = CMD_TS},
  {name = "Presentation LUT SOP Class",                  uid = "1.2.840.10008.5.1.1.23",              ts = CMD_TS},
  {name = "Basic Print Image Overlay Box SOP Class",     uid = "1.2.840.10008.5.1.1.24.1",            ts = CMD_TS},
  {name = "Media Creation Management SOP Class",         uid = "1.2.840.10008.5.1.1.33",              ts = CMD_TS},
}

-- ---------- SOP-class coverage selection ----------

-- Build the full list once (curated + extras), preserving order, and a
-- UID -> friendly-name map for rendering results back from the wire (where
-- only the abstract syntax UID is echoed). Batching, tiering and the batched
-- enumerate live in nselib/dicom.lua so the protocol limits are in one place.
local FULL_PC_LIST = {}
local NAME_BY_UID  = {}
for _, pc in ipairs(CURATED_PC_LIST) do
  FULL_PC_LIST[#FULL_PC_LIST + 1] = pc
  NAME_BY_UID[pc.uid] = pc.name
end
for _, pc in ipairs(EXTRA_PC_LIST) do
  FULL_PC_LIST[#FULL_PC_LIST + 1] = pc
  NAME_BY_UID[pc.uid] = pc.name
end

-- Select the proposal as a list of library-shape presentation contexts
-- ({abstract_syntax=, transfer_syntaxes=}). Returns (pcs, count, mode).
local function select_proposal()
  local sop = (stdnse.get_script_args("dicom-enum.sop") or "curated"):lower()
  local src = (sop == "full" or sop == "all") and FULL_PC_LIST or CURATED_PC_LIST
  local mode = (sop == "full" or sop == "all") and "full" or "curated"
  local pcs = {}
  for i, pc in ipairs(src) do
    pcs[i] = { abstract_syntax = pc.uid, transfer_syntaxes = pc.ts }
  end
  return pcs, #pcs, mode
end

-- ---------- portrule ----------

local COMMON_DICOM_PORTS = {104, 11112, 2761, 2762, 4242}

local function parse_ports_arg(s)
  if not s then return nil end
  local set = {}
  for n in string.gmatch(s, "%d+") do
    local v = tonumber(n)
    if v then set[v] = true end
  end
  return (next(set) and set) or nil
end

local custom_ports_set = parse_ports_arg(stdnse.get_script_args("dicom-enum.ports"))

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  if custom_ports_set and custom_ports_set[port.number] then return true end
  return shortport.port_or_service(COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp")(host, port)
end

-- ---------- helpers ----------

local function ts_label(uid)
  return dicom.TRANSFER_SYNTAX_NAMES[uid] or uid or "(unknown TS)"
end

-- Per-PC results other than "accepted" are a fingerprint of what the SCP
-- *doesn't* serve, useful for triage but noisy in normal output. They are
-- emitted at debug level only; the normal-output table reports "accepted".
local DEBUG_BUCKET_ORDER = {1, 3, 4, 2}

local function is_tls_port(port)
  if port.version and port.version.service_tunnel == "ssl" then return true end
  if port.version and type(port.version.name) == "string"
     and port.version.name:match("tls") then return true end
  return false
end

local function mark_dicom_service(host, port)
  local is_tls = is_tls_port(port)
  port.version.name = is_tls and "dicom-tls" or "dicom"
  nmap.set_port_version(host, port)
end

-- Render the A-ASSOCIATE-RJ details + an actionable hint into the output
-- table. Shared by every batch that comes back rejected.
local function report_reject(out, err)
  out.dicom  = "DICOM Service Provider discovered!"
  out.config = string.format("Association rejected: %s / %s / %s",
    err.result_text or "?", err.source_text or "?", err.reason_text or "?")
  if err.source == 1 and err.reason == 7 then
    out.hint = "Called-AET not recognized — try dicom.called_aet=<AET>"
  elseif err.source == 1 and err.reason == 3 then
    out.hint = "Calling-AET not recognized — try dicom.calling_aet=<AET>"
  elseif err.source == 2 and err.reason == 2 then
    out.hint = "Protocol version mismatch"
  elseif err.source == 3 and err.reason == 1 then
    out.hint = "Server overloaded — retry later"
  end
end

-- ---------- action ----------

action = function(host, port)
  local out = stdnse.output_table()

  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  local calling_aet = stdnse.get_script_args("dicom.calling_aet")
  local max_pcs     = tonumber(stdnse.get_script_args("dicom-enum.max_pcs"))

  local proposal, pc_count, sop_mode = select_proposal()
  -- Skip the fast combined pass and go straight to per-tier isolation when
  -- the operator already knows the device is hostile to mixed requests.
  local force_isolate = stdnse.get_script_args("dicom-enum.isolate") ~= nil

  local merged       = {}    -- list of {abstract_syntax, result, accepted_ts}
  local info         = nil   -- first AC PDU's user-info (max_pdu / impl_*)
  local ok_assocs    = 0
  local assoc_total  = 0
  local first_reject = nil   -- a representative A-ASSOCIATE-RJ, for reporting
  local first_error  = nil   -- a representative drop/abort/timeout, for reporting
  local tier_failed  = {}    -- [tier] = "rejects" | "drops"
  local isolated     = false -- did we fall back to per-tier isolation?

  local function absorb(acc)
    assoc_total = assoc_total + acc.assoc
    ok_assocs   = ok_assocs + acc.ok
    info        = info or acc.info
    for _, r in ipairs(acc.results) do merged[#merged + 1] = r end
  end

  -- Pass 1 (fast path): propose the whole list, batched to protocol limits by
  -- the library. Normal SCPs accept this in one association ("curated") or a
  -- few ("full"). The contexts in any batch that fails wholesale are queued
  -- for isolation.
  local to_isolate = {}
  if force_isolate then
    isolated = true
    to_isolate = proposal
  else
    local g1 = dicom.enumerate_presentation_contexts(
      host, port, calling_aet, called_aet, proposal, max_pcs)
    absorb(g1)
    for _, f in ipairs(g1.failures) do
      if dicom.is_associate_reject(f.err) then first_reject = first_reject or f.err
      else first_error = first_error or f.err end
      for _, c in ipairs(f.contexts) do to_isolate[#to_isolate + 1] = c end
    end
  end

  -- Pass 2 (isolation): a wholesale failure tells us nothing about *which*
  -- context caused it — a single Q/R abstract syntax can make some devices
  -- drop the entire association (PS3.8 §9.3.3.2 says they should reject the
  -- PC, not the association, but non-conformant devices exist). Re-probe the
  -- failed contexts one tier at a time, most-permissive first, so a hostile
  -- tier can't hide the capabilities of the others.
  if #to_isolate > 0 then
    isolated = true
    local tiers = {
      { name = "verification",   list = {} },
      { name = "core",           list = {} },
      { name = "query-retrieve", list = {} },
    }
    local by_name = {}
    for _, t in ipairs(tiers) do by_name[t.name] = t.list end
    for _, c in ipairs(to_isolate) do
      local bucket = by_name[dicom.service_tier(c.abstract_syntax)]
      bucket[#bucket + 1] = c
    end
    for _, t in ipairs(tiers) do
      if #t.list > 0 then
        local g = dicom.enumerate_presentation_contexts(
          host, port, calling_aet, called_aet, t.list, max_pcs)
        absorb(g)
        if #g.failures > 0 then
          local rep = g.failures[1].err
          tier_failed[t.name] = dicom.is_associate_reject(rep) and "rejects" or "drops"
          if dicom.is_associate_reject(rep) then first_reject = first_reject or rep
          else first_error = first_error or rep end
        end
      end
    end
  end

  -- Nothing accepted anywhere: fall back to the single-failure report so the
  -- AET / protocol-version hints still surface (today's behavior).
  if ok_assocs == 0 then
    if first_reject then
      report_reject(out, first_reject)
      mark_dicom_service(host, port)
      return out
    end
    out.dicom = "DICOM Service Provider discovered!"
    out.error = type(first_error) == "table" and (first_error.err or "error")
                or tostring(first_error or "unknown error")
    return nil
  end

  -- Resolve vendor / version once and reuse for both port.version metadata
  -- and the human-readable association header.
  local final_version, vendor, _clean, device_vendor
  if info and (info.impl_version or info.impl_uid) then
    final_version, vendor, _clean, device_vendor =
      dicom.resolve_vendor_info(info.impl_version, info.impl_uid)
  end

  if vendor then
    port.version.product = vendor
    if final_version and final_version ~= info.impl_version then
      port.version.version = final_version
    end
  end
  if device_vendor then
    port.version.extrainfo = "Device: " .. device_vendor
  end
  mark_dicom_service(host, port)

  -- Build the association header line: "accepted (max_pdu=N, vendor=...)"
  local detail = {}
  if info and info.max_pdu then
    detail[#detail + 1] = string.format("max_pdu=%d", info.max_pdu)
  end
  if vendor then
    local v = vendor
    if final_version and final_version ~= info.impl_version then
      v = v .. " " .. final_version
    end
    detail[#detail + 1] = "vendor=" .. v
  end
  if device_vendor then
    detail[#detail + 1] = "device=" .. device_vendor
  end
  if #detail > 0 then
    out.association = string.format("accepted (%s)", table.concat(detail, ", "))
  else
    out.association = "accepted"
  end

  -- Note the proposal scope when it spanned more than one association, so the
  -- output is self-describing about how thorough the scan was.
  if sop_mode == "full" or assoc_total > 1 then
    out.scan = string.format("%s coverage: %d SOP classes across %d association(s)%s",
      sop_mode, pc_count, assoc_total,
      isolated and "; isolated failing groups by tier" or "")
  end

  -- Surface non-conformant negotiation behavior discovered during isolation.
  -- These are strong device fingerprints in their own right (and explain why
  -- a naive single-association scan "just fails" against such a device).
  if tier_failed["query-retrieve"] then
    out.quirk_query_retrieve = string.format(
      "%s the whole association when a Query/Retrieve SOP class is proposed "
      .. "(non-conformant; Q/R isolated so other contexts still enumerate). "
      .. "Often a Q/R *SCU* — it queries other nodes rather than serving Q/R.",
      tier_failed["query-retrieve"] == "rejects" and "Rejects" or "Drops/aborts")
  end
  if tier_failed["core"] then
    out.quirk_operations = string.format(
      "%s associations proposing non-Verification operations while accepting "
      .. "Verification — AET/allowlist enforcement likely applies to "
      .. "Storage/operations but not to C-ECHO.",
      tier_failed["core"] == "rejects" and "Rejects" or "Drops/aborts")
  end
  if tier_failed["verification"] then
    out.quirk_verification = string.format(
      "%s a Verification-only association.",
      tier_failed["verification"] == "rejects" and "Rejects" or "Drops/aborts")
  end

  -- Bucket per-PC results and collect accepted service classes / UIDs.
  local buckets = { [0]={}, [1]={}, [2]={}, [3]={}, [4]={}, unknown={} }
  local accepted_services = {}
  local accepted_uids = {}
  for _, r in ipairs(merged) do
    local code = r.result
    local name = NAME_BY_UID[r.abstract_syntax] or r.abstract_syntax
    if code == 0 then
      table.insert(buckets[0], string.format("%s - %s", name, ts_label(r.accepted_ts)))
      accepted_uids[#accepted_uids + 1] = r.abstract_syntax
      local svc = dicom.service_class_for_uid(r.abstract_syntax)
      if svc then accepted_services[svc] = true end
    elseif code == 1 or code == 2 or code == 3 or code == 4 then
      table.insert(buckets[code], name)
    else
      table.insert(buckets.unknown, name)
    end
  end

  -- Service-class summary (sorted for stable output).
  local svc_list = {}
  for s in pairs(accepted_services) do svc_list[#svc_list + 1] = s end
  table.sort(svc_list)
  if #svc_list > 0 then
    out.service_classes = svc_list
  end

  -- DIMSE service commands implied by the accepted SOP classes
  -- (C-ECHO from Verification, C-STORE from Storage, C-FIND/MOVE/GET from
  -- Q/R + Modality Worklist).
  local cmds = dicom.infer_service_commands(accepted_uids)
  if #cmds > 0 then
    out.service_commands = cmds
  end

  -- Imaging modalities implied by accepted Storage SOP classes (CT, MRI,
  -- Ultrasound, Mammography, X-Ray, PET, Fluoroscopy, Endoscopy, ...).
  local modalities = dicom.infer_modalities(accepted_uids)
  if #modalities > 0 then
    out.modalities = modalities
  end

  -- Device-class fingerprint (practitioner taxonomy, not normative DICOM).
  local device_class = dicom.infer_device_class(accepted_services)
  if device_class then
    out.inferred_device_class = device_class
  end

  -- Structured results in normal output: only the accepted bucket. The
  -- non-accepted buckets are a fingerprint of what the SCP *doesn't* serve;
  -- emit them at debug level so normal output stays focused on capabilities.
  local results = stdnse.output_table()
  if #buckets[0] > 0 then
    local sub = stdnse.output_table()
    sub.count = #buckets[0]
    sub.items = buckets[0]
    results[dicom.PC_RESULT_NAMES[0]] = sub
  end
  out.results = results

  for _, code in ipairs(DEBUG_BUCKET_ORDER) do
    local items = buckets[code]
    if items and #items > 0 then
      stdnse.debug1("DICOM: %s (%d): %s",
        dicom.PC_RESULT_NAMES[code], #items, table.concat(items, ", "))
    end
  end
  if #buckets.unknown > 0 then
    stdnse.debug1("DICOM: unknown-result (%d): %s",
      #buckets.unknown, table.concat(buckets.unknown, ", "))
  end

  return out
end
