local datetime = require "datetime"
local dicom = require "dicom"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Fingerprints a DICOM Service Class Provider (SCP) and enumerates the SOP
classes and transfer syntaxes it accepts, by proposing a curated set of
presentation contexts in an A-ASSOCIATE request and reading the per-context
result map in the A-ASSOCIATE-AC (PS3.8 section 9.3.3.2).

No DIMSE messages or patient data are sent, and the whole catalogue goes out
in one association (two for the "full" probe at the default limits), with
associations serialized per host so the script holds at most one slot of the
SCP's association pool at a time.

From the accepted contexts the script reports:
  services          one line per accepted PS3.4 Service Class (verification,
                    storage, query, retrieve, modality_worklist,
                    storage_commitment, mpps, ups, print) with the
                    negotiated DIMSE operations and the Q/R information
                    models or UPS / Print SOP classes behind them, plus
                    "gated" when Query/Retrieve triggers an AE-title reject.
                    With -v, services that answered "no" or were "not probed"
                    at this probe depth are also listed. C-FIND is attributed
                    to query or modality_worklist by the information model it
                    runs against.
  service_classes   (-v) the accepted Service Classes, with Query/Retrieve
                    named by information model (QR-Patient-Root,
                    QR-Study-Root, QR-Patient-Study).
  service_commands  (-v) the DIMSE-C and DIMSE-N operations those SOP
                    classes carry.
  modalities        the imaging modalities implied by the accepted Storage
                    SOP classes. PET-CT is reported when both PET and CT are
                    accepted.
  inferred_device_class
                    PACS/VNA, Modality, RIS gateway, Archive front-end or
                    Print server. This is a practitioner taxonomy, not a
                    DICOM concept; treat it as a fingerprint.
  transfer_syntaxes all transfer syntaxes (uncompressed, Deflate, JPEG,
                    JPEG-LS, JPEG 2000, HTJ2K, RLE, Explicit VR Big Endian)
                    accepted by the SCP across the single-syntax codec
                    contexts proposed in "standard" and "full" modes.
  results           accepted SOP class count, each accepted SOP class with
                    the transfer syntax the SCP chose for it (listed in full
                    up to 10 or with -v), and a one-line-per-reason count of
                    any rejected SOP classes. The full list of rejected
                    contexts is listed at debug level (-d).
  security          the transport, the TLS certificate when there is one,
                    and findings drawn from the association alone: no
                    AE-title allowlist (or Q/R-only allowlist), Query/Retrieve
                    and C-STORE exposure, plaintext transport, a weak or
                    self-signed certificate, and no mutual TLS.

An accepted context means the SCP will accept requests for that SOP class,
not that an operation will succeed: destination AE allowlists, storage
policy and DIMSE-level refusals are separate layers. Because a multi-syntax
presentation context only reveals the single transfer syntax the SCP
preferred (PS3.8 section 9.3.3.2), "standard" and "full" also append one
single-syntax context per candidate codec inside the same association so
every enabled compression codec is discovered with zero extra associations.
Scripts such as dicom-cfind-ls, dicom-cmove, dicom-get and
dicom-store-inject test the DIMSE operations themselves.

Every context is proposed with Implicit VR Little Endian included as the
universal fallback (PS3.5 section 10.1), so even old devices negotiate. The
dicom-info.probe argument trades breadth against A-ASSOCIATE-RQ size:
  basic     core SOP classes, Explicit and Implicit VR only (about 3 KB;
            for fragile or embedded legacy devices)
  standard  core SOP classes with the commonly negotiated compressed
            transfer syntaxes (about 7 KB; the default)
  full      core and long-tail SOP classes (multi-frame SC, RT, extended SR,
            3D X-Ray/CBCT, spatial registration, UPS, ophthalmic, waveform,
            segmentation, whole-slide, legacy retired US/Q-R, ...) with
            every transfer syntax (about 29 KB, split across two
            associations at the default dicom.max_pcs / dicom.max_rq_bytes)
The probe line records the depth, the contexts proposed and the
associations used, so a "not probed" service or a difference between two
scans can be traced to the depth. If an older or embedded SCP aborts or
resets a multi-kilobyte proposal while still accepting a minimal
Verification request, the script automatically steps down to "basic" in
small 4 KB / 16-context batches.

The script does not guess Application Entity Titles. If the SCP enforces an
AE-title allowlist it rejects the association and the script reports the
reason; find a valid title with dicom-brute and pass it with
dicom.called_aet (or dicom-info.called_ae) and dicom.calling_aet (or
dicom-info.calling_ae).
]]

---
-- @usage nmap -p 104,4242,11112 --script dicom-info <target>
-- @usage nmap -sV --script dicom-info --script-args dicom-info.probe=full <target>
-- @usage nmap -p 11112 --script dicom-info --script-args dicom.called_aet=ORTHANC <target>
-- @usage nmap -p 2762 --script dicom-info --script-args dicom.tls=true <target>
-- @usage nmap --script dicom-info --script-args dicom-info.ports=11114 <target>
--
-- @args dicom-info.probe      Probe depth: "basic", "standard" or "full"
--                             (see the description). Default: standard
-- @args dicom-info.called_ae  Called AE Title override (falls back to
--                             dicom.called_aet, then ANY-SCP).
-- @args dicom-info.calling_ae Calling AE Title override (falls back to
--                             dicom.calling_aet, then ECHOSCU).
-- @args dicom-info.timeout    Socket timeout in seconds (falls back to
--                             dicom.timeout_ms, default 3s).
-- @args dicom-info.max_pdu    Maximum PDU length proposed in A-ASSOCIATE-RQ
--                             (default: 16384).
-- @args dicom-info.ports      Optional comma-separated list of extra ports
--                             to run on, e.g. "11114,11115", for SCPs on
--                             non-standard ports that -sV does not identify
--                             as DICOM.
--
-- @output
-- PORT      STATE SERVICE
-- 11112/tcp open  dicom
-- | dicom-info:
-- |   association: accepted (max_pdu=16382, vendor=pynetdicom 3.0.4)
-- |   probe: standard (36 SOP classes + 8 transfer syntaxes proposed, 1 association)
-- |   services:
-- |     verification: yes - C-ECHO
-- |     storage: yes - C-STORE (25 SOP classes)
-- |     query: yes - C-FIND (Patient Root, Study Root)
-- |     retrieve: yes - C-GET, C-MOVE (Patient Root, Study Root)
-- |     modality_worklist: yes - C-FIND
-- |   modalities:
-- |     CT
-- |     MRI
-- |     PET
-- |     PET-CT
-- |     Ultrasound
-- |   inferred_device_class: PACS/VNA
-- |   transfer_syntaxes:
-- |     Explicit VR Little Endian
-- |     Implicit VR Little Endian
-- |     JPEG 2000 Image Compression (Lossless Only)
-- |   results:
-- |     accepted:
-- |       count: 33
-- |       note: use -v to list all 33 accepted contexts
-- |     rejected:
-- |       3 abstract-syntax-not-supported
-- |   security:
-- |     transport: plaintext (no TLS)
-- |     findings:
-- |       Any called-AET accepted - no AE-title allowlist enforced
-- |       Query/Retrieve (C-FIND, C-GET, C-MOVE) accepted - patient/study enumeration and image retrieval surface
-- |       25 Storage SOP classes accepted - unauthenticated C-STORE (data/malware injection) surface
-- |_      Plaintext transport - associations and PHI exposed on the wire (consider DICOM-over-TLS, PS3.15 Annex B)
--
-- @output
-- PORT      STATE SERVICE
-- 11112/tcp open  dicom
-- | dicom-info:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Association rejected: rejected-permanent / DICOM-UL-service-user / called-AE-title-not-recognized
-- |_  hint: Called-AET not recognized - try dicom.called_aet=<AET>
--
-- @xmloutput
-- <elem key="association">accepted (max_pdu=16382, vendor=pynetdicom 3.0.4)</elem>
-- <elem key="probe">standard (36 SOP classes + 8 transfer syntaxes proposed, 1 association)</elem>
-- <table key="services">
--   <elem key="verification">yes - C-ECHO</elem>
--   <elem key="storage">yes - C-STORE (25 SOP classes)</elem>
--   <elem key="query">yes - C-FIND (Patient Root, Study Root)</elem>
--   <elem key="retrieve">yes - C-GET, C-MOVE (Patient Root, Study Root)</elem>
--   <elem key="modality_worklist">yes - C-FIND</elem>
-- </table>
-- <table key="modalities">
--   <elem>CT</elem>
--   <elem>MRI</elem>
-- </table>
-- <elem key="inferred_device_class">PACS/VNA</elem>
-- <table key="transfer_syntaxes">
--   <elem>Explicit VR Little Endian</elem>
--   <elem>Implicit VR Little Endian</elem>
-- </table>
-- <table key="results">
--   <table key="accepted">
--     <elem key="count">33</elem>
--     <elem key="note">use -v to list all 33 accepted contexts</elem>
--   </table>
--   <table key="rejected">
--     <elem>3 abstract-syntax-not-supported</elem>
--   </table>
-- </table>
-- <table key="security">
--   <elem key="transport">plaintext (no TLS)</elem>
--   <table key="findings">
--     <elem>Any called-AET accepted - no AE-title allowlist enforced</elem>
--   </table>
-- </table>
--
-- @see dicom-ping.nse
-- @see dicom-brute.nse
-- @see dicom-cfind-ls.nse
---

author = {
  "Paulino Calderon <paulino()calderonpale.com>",
  "Tyler M <tmart234()gmail.com>",
  "Nichelle Gilbert <nich.gilbert()gmail.com>",
}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

local COMMON_DICOM_PORTS = {104, 2761, 2762, 4242, 11112}

-- Parse a comma/space separated port list (or Lua table from --script-args)
-- into a lookup set.
local function parse_ports_arg(s)
  if not s then return nil end
  local set = {}
  if type(s) == "table" then
    for _, v in pairs(s) do
      local n = tonumber(v)
      if n then set[n] = true end
    end
  else
    for n in string.gmatch(tostring(s), "%d+") do
      set[tonumber(n)] = true
    end
  end
  return next(set) and set or nil
end

local custom_ports = parse_ports_arg(stdnse.get_script_args(SCRIPT_NAME .. ".ports"))
local default_portrule = shortport.port_or_service(COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp", "open")

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  if custom_ports and custom_ports[port.number] then return true end
  return default_portrule(host, port)
end

-- ---------- Presentation context catalogue ----------

local TS = dicom.TRANSFER_SYNTAX

-- Storage transfer syntax sets, chosen per probe depth. Explicit VR LE leads
-- so SCPs that pick in client-preference order report Explicit VR rather than
-- masking it behind Implicit VR LE; Implicit VR LE is always present as the
-- universal fallback (PS3.5 section 10.1) so legacy Implicit-only devices and
-- compressed-only SOP classes still negotiate cleanly.
local TS_STORAGE = {
  basic = { TS.EXPLICIT_LE, TS.IMPLICIT_LE },
  standard = {
    TS.EXPLICIT_LE, TS.DEFLATED_LE, TS.JPEG_LOSSLESS,
    TS.JPEG2000_LOSSLESS, TS.JPEG2000, TS.JPEG_BASELINE, TS.RLE,
    TS.IMPLICIT_LE,
  },
  full = {
    TS.EXPLICIT_LE, TS.DEFLATED_LE, TS.EXPLICIT_BE,
    TS.JPEG_LOSSLESS, TS.JPEG_LOSSLESS_NH, TS.JPEG_LS, TS.JPEG_LS_LOSSY,
    TS.JPEG2000_LOSSLESS, TS.JPEG2000, TS.JPEG_BASELINE, TS.JPEG_EXTENDED,
    TS.HTJ2K_LOSSLESS, TS.HTJ2K_LOSSLESS_RPCL, TS.HTJ2K, TS.RLE,
    TS.IMPLICIT_LE,
  },
}

-- Non-storage classes (Verification, Q/R, MWL, MPPS, Storage Commitment,
-- UPS, Print) gain nothing from compressed transfer syntaxes.
local TS_CMD = { TS.EXPLICIT_LE, TS.IMPLICIT_LE }

-- kind  = "storage" (gets the depth's storage transfer syntaxes) or "cmd"
--         (always TS_CMD).
-- depth = "core" (proposed at every depth) or "ext" (only by "full"): the
--         broadly supported surface versus the long tail that matters for
--         exhaustive fingerprinting of modern systems.
-- UIDs are from PS3.4 and the PS3.6 UID registry.
local CATALOGUE = {
  -- Verification
  {name = "Verification",                                uid = "1.2.840.10008.1.1",                   kind = "cmd",     depth = "core"},

  -- Storage (core)
  {name = "CT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.2",           kind = "storage", depth = "core"},
  {name = "Enhanced CT Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.2.1",         kind = "storage", depth = "core"},
  {name = "MR Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.4",           kind = "storage", depth = "core"},
  {name = "Enhanced MR Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.4.1",         kind = "storage", depth = "core"},
  {name = "Ultrasound Image Storage",                    uid = "1.2.840.10008.5.1.4.1.1.6.1",         kind = "storage", depth = "core"},
  {name = "Ultrasound Multi-frame Image Storage",        uid = "1.2.840.10008.5.1.4.1.1.3.1",         kind = "storage", depth = "core"},
  {name = "Computed Radiography Image Storage",          uid = "1.2.840.10008.5.1.4.1.1.1",           kind = "storage", depth = "core"},
  {name = "Digital X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.1",      kind = "storage", depth = "core"},
  {name = "Digital X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.1.1",    kind = "storage", depth = "core"},
  {name = "Digital Mammography X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.2",   kind = "storage", depth = "core"},
  {name = "Digital Mammography X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.2.1", kind = "storage", depth = "core"},
  {name = "X-Ray Angiographic Image Storage",            uid = "1.2.840.10008.5.1.4.1.1.12.1",        kind = "storage", depth = "core"},
  {name = "Enhanced X-Ray Angiographic Image Storage",   uid = "1.2.840.10008.5.1.4.1.1.12.1.1",      kind = "storage", depth = "core"},
  {name = "X-Ray Radiofluoroscopic Image Storage",       uid = "1.2.840.10008.5.1.4.1.1.12.2",        kind = "storage", depth = "core"},
  {name = "Enhanced X-Ray Radiofluoroscopic Image Storage", uid = "1.2.840.10008.5.1.4.1.1.12.2.1",   kind = "storage", depth = "core"},
  {name = "Nuclear Medicine Image Storage",              uid = "1.2.840.10008.5.1.4.1.1.20",          kind = "storage", depth = "core"},
  {name = "Positron Emission Tomography Image Storage",  uid = "1.2.840.10008.5.1.4.1.1.128",         kind = "storage", depth = "core"},
  {name = "Enhanced PET Image Storage",                  uid = "1.2.840.10008.5.1.4.1.1.130",         kind = "storage", depth = "core"},
  {name = "VL Endoscopic Image Storage",                 uid = "1.2.840.10008.5.1.4.1.1.77.1.1",      kind = "storage", depth = "core"},
  {name = "Video Endoscopic Image Storage",              uid = "1.2.840.10008.5.1.4.1.1.77.1.1.1",    kind = "storage", depth = "core"},
  {name = "Secondary Capture Image Storage",             uid = "1.2.840.10008.5.1.4.1.1.7",           kind = "storage", depth = "core"},
  {name = "Encapsulated PDF Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.1",       kind = "storage", depth = "core"},
  {name = "Basic Text SR Storage",                       uid = "1.2.840.10008.5.1.4.1.1.88.11",       kind = "storage", depth = "core"},
  {name = "Comprehensive SR Storage",                    uid = "1.2.840.10008.5.1.4.1.1.88.33",       kind = "storage", depth = "core"},
  {name = "Grayscale Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.1",      kind = "storage", depth = "core"},

  -- Storage (long tail, full probe only)
  {name = "Enhanced US Volume Storage",                  uid = "1.2.840.10008.5.1.4.1.1.6.2",         kind = "storage", depth = "ext"},
  {name = "Ultrasound Image Storage (Retired)",          uid = "1.2.840.10008.5.1.4.1.1.6",           kind = "storage", depth = "ext"},
  {name = "Ultrasound Multi-frame Image Storage (Retired)", uid = "1.2.840.10008.5.1.4.1.1.3",        kind = "storage", depth = "ext"},
  {name = "Digital Intra-Oral X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.3", kind = "storage", depth = "ext"},
  {name = "Breast Tomosynthesis Image Storage",          uid = "1.2.840.10008.5.1.4.1.1.13.1.3",      kind = "storage", depth = "ext"},
  {name = "X-Ray 3D Angiographic Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.13.1.1",      kind = "storage", depth = "ext"},
  {name = "X-Ray 3D Craniofacial Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.13.1.2",      kind = "storage", depth = "ext"},
  {name = "Legacy Converted Enhanced PET Image Storage", uid = "1.2.840.10008.5.1.4.1.1.128.1",       kind = "storage", depth = "ext"},
  {name = "Multi-frame Single Bit SC Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.7.1",         kind = "storage", depth = "ext"},
  {name = "Multi-frame Grayscale Byte SC Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.2",         kind = "storage", depth = "ext"},
  {name = "Multi-frame Grayscale Word SC Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.3",         kind = "storage", depth = "ext"},
  {name = "Multi-frame True Color SC Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.7.4",         kind = "storage", depth = "ext"},
  {name = "Enhanced SR Storage",                         uid = "1.2.840.10008.5.1.4.1.1.88.22",       kind = "storage", depth = "ext"},
  {name = "Comprehensive 3D SR Storage",                 uid = "1.2.840.10008.5.1.4.1.1.88.34",       kind = "storage", depth = "ext"},
  {name = "Key Object Selection Document Storage",       uid = "1.2.840.10008.5.1.4.1.1.88.59",       kind = "storage", depth = "ext"},
  {name = "Color Softcopy Presentation State Storage",   uid = "1.2.840.10008.5.1.4.1.1.11.2",        kind = "storage", depth = "ext"},
  {name = "Spatial Registration Storage",                uid = "1.2.840.10008.5.1.4.1.1.66.1",        kind = "storage", depth = "ext"},
  {name = "Segmentation Storage",                        uid = "1.2.840.10008.5.1.4.1.1.66.4",        kind = "storage", depth = "ext"},
  {name = "Surface Segmentation Storage",                uid = "1.2.840.10008.5.1.4.1.1.66.5",        kind = "storage", depth = "ext"},
  {name = "Parametric Map Storage",                      uid = "1.2.840.10008.5.1.4.1.1.30",          kind = "storage", depth = "ext"},
  {name = "Raw Data Storage",                            uid = "1.2.840.10008.5.1.4.1.1.66",          kind = "storage", depth = "ext"},
  {name = "VL Microscopic Image Storage",                uid = "1.2.840.10008.5.1.4.1.1.77.1.2",      kind = "storage", depth = "ext"},
  {name = "VL Photographic Image Storage",               uid = "1.2.840.10008.5.1.4.1.1.77.1.4",      kind = "storage", depth = "ext"},
  {name = "VL Whole Slide Microscopy Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.77.1.6",      kind = "storage", depth = "ext"},
  {name = "Ophthalmic Photography 8 Bit Image Storage",  uid = "1.2.840.10008.5.1.4.1.1.77.1.5.1",    kind = "storage", depth = "ext"},
  {name = "Ophthalmic Photography 16 Bit Image Storage", uid = "1.2.840.10008.5.1.4.1.1.77.1.5.2",    kind = "storage", depth = "ext"},
  {name = "Ophthalmic Tomography Image Storage",         uid = "1.2.840.10008.5.1.4.1.1.77.1.5.4",    kind = "storage", depth = "ext"},
  {name = "12-lead ECG Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.1.1",       kind = "storage", depth = "ext"},
  {name = "General ECG Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.1.2",       kind = "storage", depth = "ext"},
  {name = "Ambulatory ECG Waveform Storage",             uid = "1.2.840.10008.5.1.4.1.1.9.1.3",       kind = "storage", depth = "ext"},
  {name = "Hemodynamic Waveform Storage",                uid = "1.2.840.10008.5.1.4.1.1.9.2.1",       kind = "storage", depth = "ext"},
  {name = "RT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.481.1",       kind = "storage", depth = "ext"},
  {name = "RT Dose Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.2",       kind = "storage", depth = "ext"},
  {name = "RT Structure Set Storage",                    uid = "1.2.840.10008.5.1.4.1.1.481.3",       kind = "storage", depth = "ext"},
  {name = "RT Plan Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.5",       kind = "storage", depth = "ext"},
  {name = "RT Ion Plan Storage",                         uid = "1.2.840.10008.5.1.4.1.1.481.8",       kind = "storage", depth = "ext"},
  {name = "Encapsulated CDA Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.2",       kind = "storage", depth = "ext"},
  {name = "Encapsulated STL Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.3",       kind = "storage", depth = "ext"},
  {name = "Surface Scan Mesh Storage",                   uid = "1.2.840.10008.5.1.4.1.1.68.1",        kind = "storage", depth = "ext"},

  -- Worklist and Query/Retrieve
  {name = "Modality Worklist Information Model - FIND",  uid = "1.2.840.10008.5.1.4.31",              kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - FIND",          uid = "1.2.840.10008.5.1.4.1.2.1.1",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - MOVE",          uid = "1.2.840.10008.5.1.4.1.2.1.2",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - GET",           uid = "1.2.840.10008.5.1.4.1.2.1.3",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - FIND",            uid = "1.2.840.10008.5.1.4.1.2.2.1",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - MOVE",            uid = "1.2.840.10008.5.1.4.1.2.2.2",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - GET",             uid = "1.2.840.10008.5.1.4.1.2.2.3",         kind = "cmd",     depth = "core"},
  {name = "Patient/Study Only Query/Retrieve - FIND (Retired)", uid = "1.2.840.10008.5.1.4.1.2.3.1",  kind = "cmd",     depth = "ext"},
  {name = "Patient/Study Only Query/Retrieve - MOVE (Retired)", uid = "1.2.840.10008.5.1.4.1.2.3.2",  kind = "cmd",     depth = "ext"},

  -- Workflow
  {name = "Storage Commitment Push Model",               uid = "1.2.840.10008.1.20.1",                kind = "cmd",     depth = "core"},
  {name = "Modality Performed Procedure Step",           uid = "1.2.840.10008.3.1.2.3.3",             kind = "cmd",     depth = "core"},
  {name = "Unified Procedure Step - Push",               uid = "1.2.840.10008.5.1.4.34.6.1",          kind = "cmd",     depth = "ext"},
  {name = "Unified Procedure Step - Watch",              uid = "1.2.840.10008.5.1.4.34.6.2",          kind = "cmd",     depth = "ext"},
  {name = "Unified Procedure Step - Pull",               uid = "1.2.840.10008.5.1.4.34.6.3",          kind = "cmd",     depth = "ext"},

  -- Print
  {name = "Basic Grayscale Print Management Meta",       uid = "1.2.840.10008.5.1.1.9",               kind = "cmd",     depth = "core"},
  {name = "Basic Color Print Management Meta",           uid = "1.2.840.10008.5.1.1.18",              kind = "cmd",     depth = "ext"},
}

-- Build the presentation contexts for a probe depth, plus the parallel list
-- of catalogue entries they came from. In "standard" and "full" modes, also
-- append one single-syntax presentation context per codec in TS_STORAGE[depth]
-- against CT Image Storage (PS3.8 section 9.3.2.2 allows multiple contexts
-- per Abstract Syntax), so every supported Transfer Syntax is enumerated
-- individually inside the existing association(s) with zero extra round-trips.
local function build_pcs(depth)
  local pcs, entries = {}, {}
  for _, e in ipairs(CATALOGUE) do
    if e.depth == "core" or depth == "full" then
      local ts = (e.kind == "storage") and TS_STORAGE[depth] or TS_CMD
      pcs[#pcs + 1] = { abstract_syntax = e.uid, transfer_syntaxes = ts }
      entries[#entries + 1] = e
    end
  end
  if depth ~= "basic" then
    for _, ts_uid in ipairs(TS_STORAGE[depth]) do
      pcs[#pcs + 1] = {
        abstract_syntax   = dicom.SOP_CLASS.CT_IMAGE_STORAGE,
        transfer_syntaxes = { ts_uid },
      }
      entries[#entries + 1] = { is_ts_probe = true, ts_uid = ts_uid }
    end
  end
  return pcs, entries
end

-- ---------- SOP class classification ----------

-- PS3.4 Service Classes in services-table order. Query/Retrieve (Annex C) is
-- split into its query (C-FIND) and retrieve (C-MOVE, C-GET) halves;
-- Modality Worklist is the Basic Worklist Management Service (Annex K), a
-- separate Service Class whose C-FIND runs against a different information
-- model.
local SERVICE_KEYS = {
  "verification",        -- Annex A
  "storage",             -- Annex B
  "query",               -- Annex C, C-FIND
  "retrieve",            -- Annex C, C-MOVE / C-GET
  "modality_worklist",   -- Annex K
  "storage_commitment",  -- Annex J
  "mpps",                -- Annex F
  "ups",                 -- Annex CC
  "print",               -- Annex H
}

-- Service Class names for service_classes; Query/Retrieve is named by
-- information model instead (QR_MODELS).
local SERVICE_CLASS_NAMES = {
  verification       = "Verification",
  storage            = "Storage",
  modality_worklist  = "Modality-Worklist",
  storage_commitment = "Storage-Commitment",
  mpps               = "MPPS",
  ups                = "UPS",
  print              = "Print",
}

-- DIMSE operations each SOP Class carries (PS3.4; DIMSE services per PS3.7).
-- Composite services use DIMSE-C, the normalized workflow and print services
-- use DIMSE-N. A Meta SOP Class lists the union of its member SOP Classes.
local PRINT_META_OPS = {"N-ACTION", "N-CREATE", "N-DELETE", "N-EVENT-REPORT", "N-GET", "N-SET"}
local DIMSE_BY_UID = {
  ["1.2.840.10008.1.1"]          = {service = "verification",       ops = {"C-ECHO"}},
  ["1.2.840.10008.5.1.4.31"]     = {service = "modality_worklist",  ops = {"C-FIND"}},
  ["1.2.840.10008.1.20.1"]       = {service = "storage_commitment", ops = {"N-ACTION", "N-EVENT-REPORT"}},
  ["1.2.840.10008.3.1.2.3.3"]    = {service = "mpps",               ops = {"N-CREATE", "N-SET"}},
  -- Each UPS SOP Class carries a different slice of the service (Annex CC).
  ["1.2.840.10008.5.1.4.34.6.1"] = {service = "ups", label = "Push",  ops = {"N-ACTION", "N-CREATE", "N-GET"}},
  ["1.2.840.10008.5.1.4.34.6.2"] = {service = "ups", label = "Watch", ops = {"C-FIND", "N-ACTION", "N-GET"}},
  ["1.2.840.10008.5.1.4.34.6.3"] = {service = "ups", label = "Pull",  ops = {"C-FIND", "N-ACTION", "N-GET", "N-SET"}},
  ["1.2.840.10008.5.1.4.34.6.4"] = {service = "ups", label = "Event", ops = {"N-EVENT-REPORT"}},
  -- Trial UPS SOP Classes (PS3.6 retired; .32.1-.3 are retired GPWL, not UPS).
  ["1.2.840.10008.5.1.4.34.4.1"] = {service = "ups", label = "Push",  ops = {"N-ACTION", "N-CREATE", "N-GET"}},
  ["1.2.840.10008.5.1.4.34.4.2"] = {service = "ups", label = "Watch", ops = {"C-FIND", "N-ACTION", "N-GET"}},
  ["1.2.840.10008.5.1.4.34.4.3"] = {service = "ups", label = "Pull",  ops = {"C-FIND", "N-ACTION", "N-GET", "N-SET"}},
  ["1.2.840.10008.5.1.4.34.4.4"] = {service = "ups", label = "Event", ops = {"N-EVENT-REPORT"}},
  ["1.2.840.10008.5.1.1.9"]      = {service = "print", label = "Basic Grayscale", ops = PRINT_META_OPS},
  ["1.2.840.10008.5.1.1.18"]     = {service = "print", label = "Basic Color",     ops = PRINT_META_OPS},
}

local STORAGE_UID_PREFIX = "1.2.840.10008.5.1.4.1.1."
-- Q/R SOP Class UIDs are <information model>.<op>: .1 FIND, .2 MOVE, .3 GET.
local QR_UID_PREFIX = "1.2.840.10008.5.1.4.1.2."
local QR_OPS = { ["1"] = "C-FIND", ["2"] = "C-MOVE", ["3"] = "C-GET" }
local QR_MODELS = {
  ["1.2.840.10008.5.1.4.1.2.1"] = {label = "Patient Root",       class = "QR-Patient-Root"},
  ["1.2.840.10008.5.1.4.1.2.2"] = {label = "Study Root",         class = "QR-Study-Root"},
  ["1.2.840.10008.5.1.4.1.2.3"] = {label = "Patient/Study Only", class = "QR-Patient-Study"},
}

-- Classify a SOP Class UID. Returns its SERVICE_KEYS entry, the DIMSE
-- operations it carries, an optional label naming the Q/R information model
-- or UPS / Print SOP Class, and its Service Class name; nil if unknown.
local function classify(uid)
  local d = DIMSE_BY_UID[uid]
  if d then
    return d.service, d.ops, d.label, SERVICE_CLASS_NAMES[d.service]
  end
  if uid:sub(1, #STORAGE_UID_PREFIX) == STORAGE_UID_PREFIX then
    return "storage", {"C-STORE"}, nil, SERVICE_CLASS_NAMES.storage
  end
  if uid:sub(1, #QR_UID_PREFIX) == QR_UID_PREFIX then
    local model, tail = uid:match("^(.*)%.(%d)$")
    local qr, op = QR_MODELS[model], QR_OPS[tail]
    if qr and op then
      return (op == "C-FIND") and "query" or "retrieve", {op}, qr.label, qr.class
    end
  end
  return nil
end

-- Storage SOP Class UID -> imaging modality (PS3.4 Annex B, PS3.6).
local MODALITY_BY_UID = {
  ["1.2.840.10008.5.1.4.1.1.2"]        = "CT",
  ["1.2.840.10008.5.1.4.1.1.2.1"]      = "CT",
  ["1.2.840.10008.5.1.4.1.1.2.2"]      = "CT",
  ["1.2.840.10008.5.1.4.1.1.4"]        = "MRI",
  ["1.2.840.10008.5.1.4.1.1.4.1"]      = "MRI",
  ["1.2.840.10008.5.1.4.1.1.4.2"]      = "MRI",
  ["1.2.840.10008.5.1.4.1.1.4.3"]      = "MRI",
  ["1.2.840.10008.5.1.4.1.1.4.4"]      = "MRI",
  ["1.2.840.10008.5.1.4.1.1.3"]        = "Ultrasound",
  ["1.2.840.10008.5.1.4.1.1.3.1"]      = "Ultrasound",
  ["1.2.840.10008.5.1.4.1.1.6"]        = "Ultrasound",
  ["1.2.840.10008.5.1.4.1.1.6.1"]      = "Ultrasound",
  ["1.2.840.10008.5.1.4.1.1.6.2"]      = "Ultrasound",
  ["1.2.840.10008.5.1.4.1.1.1.2"]      = "Mammography",
  ["1.2.840.10008.5.1.4.1.1.1.2.1"]    = "Mammography",
  ["1.2.840.10008.5.1.4.1.1.13.1.3"]   = "Mammography",
  ["1.2.840.10008.5.1.4.1.1.1.3"]      = "X-Ray (Intra-oral)",
  ["1.2.840.10008.5.1.4.1.1.1.3.1"]    = "X-Ray (Intra-oral)",
  ["1.2.840.10008.5.1.4.1.1.1.1"]      = "X-Ray (DX)",
  ["1.2.840.10008.5.1.4.1.1.1.1.1"]    = "X-Ray (DX)",
  ["1.2.840.10008.5.1.4.1.1.1"]        = "X-Ray (CR)",
  ["1.2.840.10008.5.1.4.1.1.12.1"]     = "X-Ray Angiography",
  ["1.2.840.10008.5.1.4.1.1.12.1.1"]   = "X-Ray Angiography",
  ["1.2.840.10008.5.1.4.1.1.13.1.1"]   = "X-Ray 3D Angiography",
  ["1.2.840.10008.5.1.4.1.1.13.1.2"]   = "X-Ray 3D Craniofacial (CBCT)",
  ["1.2.840.10008.5.1.4.1.1.12.2"]     = "Fluoroscopy",
  ["1.2.840.10008.5.1.4.1.1.12.2.1"]   = "Fluoroscopy",
  ["1.2.840.10008.5.1.4.1.1.20"]       = "Nuclear Medicine",
  -- PET-CT scanners emit both PET and CT Storage SOP classes.
  ["1.2.840.10008.5.1.4.1.1.128"]      = "PET",
  ["1.2.840.10008.5.1.4.1.1.128.1"]    = "PET",
  ["1.2.840.10008.5.1.4.1.1.130"]      = "PET",
  ["1.2.840.10008.5.1.4.1.1.77.1.1"]   = "Endoscopy",
  ["1.2.840.10008.5.1.4.1.1.77.1.1.1"] = "Endoscopy",
  ["1.2.840.10008.5.1.4.1.1.77.1.4"]   = "VL Photographic",
  ["1.2.840.10008.5.1.4.1.1.77.1.4.1"] = "VL Photographic",
  ["1.2.840.10008.5.1.4.1.1.481.1"]    = "Radiotherapy (RT)",
  ["1.2.840.10008.5.1.4.1.1.481.2"]    = "Radiotherapy (RT)",
  ["1.2.840.10008.5.1.4.1.1.481.3"]    = "Radiotherapy (RT)",
  ["1.2.840.10008.5.1.4.1.1.481.5"]    = "Radiotherapy (RT)",
  ["1.2.840.10008.5.1.4.1.1.481.8"]    = "Radiotherapy (RT)",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.1"] = "Ophthalmic Photography",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.2"] = "Ophthalmic Photography",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.4"] = "Ophthalmic Tomography (OCT)",
  ["1.2.840.10008.5.1.4.1.1.9.1.1"]    = "ECG (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.9.1.2"]    = "ECG (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.9.1.3"]    = "ECG (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.9.2.1"]    = "Hemodynamic (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.77.1.2"]   = "Microscopy",
  ["1.2.840.10008.5.1.4.1.1.77.1.2.1"] = "Microscopy",
  ["1.2.840.10008.5.1.4.1.1.77.1.6"]   = "Whole Slide Imaging",
  -- Non-image objects, no implied physical modality
  ["1.2.840.10008.5.1.4.1.1.7"]        = "Secondary Capture",
  ["1.2.840.10008.5.1.4.1.1.104.1"]    = "Encapsulated Document",
}

local function sorted_keys(set)
  local list = {}
  for k in pairs(set) do list[#list + 1] = k end
  table.sort(list)
  return list
end

-- Summarize negotiation per SERVICE_KEYS entry. A key is absent when no
-- context for that service was answered (not probed); otherwise it maps to
-- {accepted = bool, sop_classes = n, ops = {[op] = sorted labels}}, where
-- labels name the Q/R information models or UPS / Print SOP Classes that
-- carry the op. Contexts left unanswered by a failed follow-up association
-- count as not probed rather than rejected.
local function summarize_services(pc_results, entries)
  local out = {}
  for i, r in ipairs(pc_results) do
    if not (entries[i] and entries[i].is_ts_probe) then
      local svc, ops, label = classify(r.abstract_syntax)
      if svc and r.result ~= nil then
        local s = out[svc] or { accepted = false, sop_classes = 0, ops = {} }
        out[svc] = s
        if r.result == 0 then
          s.accepted = true
          s.sop_classes = s.sop_classes + 1
          for _, op in ipairs(ops) do
            s.ops[op] = s.ops[op] or {}
            if label then s.ops[op][label] = true end
          end
        end
      end
    end
  end
  for _, s in pairs(out) do
    for op, labels in pairs(s.ops) do s.ops[op] = sorted_keys(labels) end
  end
  return out
end

-- One line per Service Class: "yes - <DIMSE ops> (<labels>)", "no", or
-- "not probed". Ops that cover the same labels share a group, e.g.
-- "yes - C-GET, C-MOVE (Patient Root, Study Root)".
local function service_line(key, s)
  if not s then return "not probed" end
  if not s.accepted then return "no" end
  if key == "storage" then
    return string.format("yes - C-STORE (%d SOP class%s)",
      s.sop_classes, s.sop_classes == 1 and "" or "es")
  end
  local groups, order = {}, {}
  for _, op in ipairs(sorted_keys(s.ops)) do
    local labels = table.concat(s.ops[op], ", ")
    if not groups[labels] then
      groups[labels] = {}
      order[#order + 1] = labels
    end
    table.insert(groups[labels], op)
  end
  local parts = {}
  for _, labels in ipairs(order) do
    local part = table.concat(groups[labels], ", ")
    if labels ~= "" then part = part .. " (" .. labels .. ")" end
    parts[#parts + 1] = part
  end
  return "yes - " .. table.concat(parts, "; ")
end

-- Best-effort device class from the accepted Service Class names. The
-- taxonomy (PACS/VNA, Modality, RIS gateway, Archive, Print) is practitioner
-- consensus, not a normative DICOM concept; cf. Mildenberger 2002 (PMID
-- 11960356). Returns nil when the pattern is ambiguous.
local function device_class(classes)
  local qr = classes["QR-Patient-Root"] or classes["QR-Study-Root"]
    or classes["QR-Patient-Study"]
  local storage = classes["Storage"]
  if storage and qr and (classes["Modality-Worklist"] or classes["MPPS"]
      or classes["Storage-Commitment"]) then
    return "PACS/VNA"
  end
  if storage and qr then return "Archive front-end" end
  if classes["Modality-Worklist"] and not storage then
    return "RIS gateway / worklist broker"
  end
  if classes["Print"] then return "Print server" end
  if classes["Verification"] and not storage and not qr then
    return "Modality (or unconfigured SCP)"
  end
  return nil
end

-- ---------- Security assessment ----------

local function cert_date(d)
  if type(d) == "table" then return datetime.format_timestamp(d) end
  return tostring(d)
end

-- Summarize a TLS certificate as an ordered output table.
local function cert_table(cert)
  local t = stdnse.output_table()
  t.subject = cert.subject and cert.subject.commonName or "?"
  t.issuer  = cert.issuer  and cert.issuer.commonName  or "?"
  if cert.validity and cert.validity.notAfter then
    t.not_after = cert_date(cert.validity.notAfter)
  end
  if cert.pubkey then
    local kline = tostring(cert.pubkey.type or "?")
    if cert.pubkey.bits then kline = kline .. " " .. tostring(cert.pubkey.bits) .. "-bit" end
    t.public_key = kline
  end
  if cert.sig_algorithm then
    t.signature = tostring(cert.sig_algorithm)
  end
  return t
end

-- Compare two X.509 Distinguished Name tables for equality (used to detect
-- self-signed certificates even when commonName is absent).
local function dn_equal(a, b)
  if type(a) ~= "table" or type(b) ~= "table" then return false end
  local count_a, count_b = 0, 0
  for k, v in pairs(a) do
    count_a = count_a + 1
    if b[k] ~= v then return false end
  end
  for _ in pairs(b) do count_b = count_b + 1 end
  return count_a > 0 and count_a == count_b
end

-- Weak-crypto, validity, and trust warnings derived from a TLS certificate.
local function cert_findings(cert, out)
  if cert.pubkey and cert.pubkey.bits then
    local ktype = tostring(cert.pubkey.type or ""):lower()
    if (ktype == "rsa" or ktype == "dsa") and cert.pubkey.bits < 2048 then
      out[#out + 1] = string.format(
        "TLS certificate uses a weak %s key (%d-bit < 2048-bit)",
        ktype:upper(), cert.pubkey.bits)
    elseif ktype == "ec" and cert.pubkey.bits < 224 then
      out[#out + 1] = string.format(
        "TLS certificate uses a weak EC key (%d-bit < 224-bit)",
        cert.pubkey.bits)
    end
  end
  if cert.sig_algorithm then
    local low = tostring(cert.sig_algorithm):lower()
    if low:find("sha1", 1, true) or low:find("md5", 1, true) then
      out[#out + 1] = "TLS certificate uses a weak signature algorithm (SHA-1/MD5)"
    end
  end
  if cert.validity then
    local now = os.time()
    if type(cert.validity.notAfter) == "table" then
      local ok_ts, exp = pcall(datetime.date_to_timestamp, cert.validity.notAfter, 0)
      if ok_ts and type(exp) == "number" and exp < now then
        out[#out + 1] = "TLS certificate is expired (notAfter: "
          .. cert_date(cert.validity.notAfter) .. ")"
      end
    end
    if type(cert.validity.notBefore) == "table" then
      local ok_ts, nb = pcall(datetime.date_to_timestamp, cert.validity.notBefore, 0)
      if ok_ts and type(nb) == "number" and nb > now then
        out[#out + 1] = "TLS certificate is not yet valid (notBefore: "
          .. cert_date(cert.validity.notBefore) .. ")"
      end
    end
  end
  if dn_equal(cert.subject, cert.issuer) then
    out[#out + 1] = "TLS certificate is self-signed (no CA trust chain)"
  end
end

-- Findings drawn from the association alone; no DIMSE messages are sent.
local function security_findings(services, called_aet, info, qr_aet_reject)
  local findings = {}

  if qr_aet_reject then
    local field = (qr_aet_reject.reason == 3) and "Calling-AET"
      or (qr_aet_reject.reason == 7) and "Called-AET" or "AE-title"
    findings[#findings + 1] = string.format(
      "Partial AE-title allowlist (Q/R + MWL only) - Verification/Storage accepted the association, while Query/Retrieve enforced %s (%s)",
      field, qr_aet_reject.reason_text or "rejected")
  elseif not called_aet or called_aet == "" or called_aet == "ANY-SCP" then
    findings[#findings + 1] = "Any called-AET accepted - no AE-title allowlist enforced"
  end

  local query, retrieve, storage = services.query, services.retrieve, services.storage
  local qr_ops = {}
  if query and query.accepted then qr_ops[#qr_ops + 1] = "C-FIND" end
  if retrieve and retrieve.ops["C-GET"] then qr_ops[#qr_ops + 1] = "C-GET" end
  if retrieve and retrieve.ops["C-MOVE"] then qr_ops[#qr_ops + 1] = "C-MOVE" end
  if #qr_ops > 0 then
    findings[#findings + 1] = string.format(
      "Query/Retrieve (%s) accepted - patient/study enumeration and image retrieval surface",
      table.concat(qr_ops, ", "))
  end
  if storage and storage.accepted then
    findings[#findings + 1] = string.format(
      "%d Storage SOP class%s accepted - unauthenticated C-STORE (data/malware injection) surface",
      storage.sop_classes, storage.sop_classes == 1 and "" or "es")
  end

  if info.tls then
    findings[#findings + 1] =
      "TLS association completed without a client certificate - no mutual TLS / IHE ATNA node authentication"
    if info.cert then cert_findings(info.cert, findings) end
  else
    findings[#findings + 1] =
      "Plaintext transport - associations and PHI exposed on the wire (consider DICOM-over-TLS, PS3.15 Annex B)"
  end

  return findings
end

-- ---------- action ----------

local PROBE_DEPTHS = { basic = true, standard = true, full = true }

-- Rejected contexts are a fingerprint of what the SCP doesn't serve: useful
-- for triage, noise in normal output, so they are listed at debug level.
local DEBUG_RESULT_ORDER = {1, 3, 4, 2}

local REJECT_HINTS = {
  [1] = {
    [3] = "Calling-AET not recognized - try dicom.calling_aet=<AET>",
    [7] = "Called-AET not recognized - try dicom.called_aet=<AET>",
  },
  [2] = {
    [2] = "Protocol version mismatch",
  },
  [3] = {
    [1] = "SCP busy (association pool full) after retries - rescan later",
    [2] = "SCP busy (association pool full) after retries - rescan later",
  },
}

local function mark_dicom_service(host, port, tls, confirmed)
  if tls == nil then tls = dicom.tls_enabled(port) end
  if confirmed == false then
    local cur = port.version and port.version.name
    if cur and cur ~= "" and cur ~= "unknown" and cur ~= "dicom" and cur ~= "dicom-tls" then
      return
    end
  end
  port.version.name = tls and "dicom-tls" or "dicom"
  nmap.set_port_version(host, port)
end

local function is_qr_uid(uid)
  local svc = classify(uid)
  return svc == "query" or svc == "retrieve" or svc == "modality_worklist"
end

local function is_aet_reject(err)
  return type(err) == "table" and err.source == 1
    and (err.reason == 3 or err.reason == 7)
end

-- Whether an error looks like a TLS handshake / mTLS rejection rather than
-- a non-DICOM application protocol banner (such as HTTP 400 on an HTTPS port).
local function is_likely_mtls_error(err)
  local s = tostring(err or "")
  if s:find("unexpected response PDU", 1, true)
      or s:find("PDU_TOO_LARGE", 1, true)
      or s:find("TRUNCATED_PDU", 1, true) then
    return false
  end
  return s:find("Failed to connect", 1, true) ~= nil
    or s:find("Couldn't send ASSOCIATE request", 1, true) ~= nil
    or s:find("CONNECTION_RESET", 1, true) ~= nil
    or s:find("EOF", 1, true) ~= nil
    or s:find("TIMEOUT", 1, true) ~= nil
    or s:find("ERROR", 1, true) ~= nil
end

local function is_expected_dicom_tls_port(port)
  if stdnse.get_script_args("dicom.tls") ~= nil then return true end
  local vname = port.version and port.version.name
  if vname == "dicom-tls" or vname == "dicom" then return true end
  if vname and vname ~= "" and vname ~= "unknown" then return false end
  if tonumber(port.number) == 2762 then return true end
  if custom_ports and custom_ports[port.number] then return true end
  return port.service == "dicom-tls" or port.service == "dicom"
end

-- Some SCPs (e.g. DCMTK/PatientIEBridge with CheckCallingAET=qronly) accept
-- any AET for Verification and Storage but reject the whole association with
-- calling/called-AE-title-not-recognized as soon as a Query/Retrieve SOP
-- class appears in the A-ASSOCIATE-RQ. When an association containing Q/R
-- fails with an AET reject, re-probe the unanswered non-Q/R contexts without
-- Q/R so the non-Q/R surface is still enumerated.
local function retry_without_qr(host, port, calling_ae, called_ae, pcs, pc_results, info, initial_err, opts)
  local non_qr_pcs, non_qr_idx, qr_count = {}, {}, 0
  for i, pc in ipairs(pcs) do
    local answered = pc_results and pc_results[i] and pc_results[i].result ~= nil
    if not answered then
      if is_qr_uid(pc.abstract_syntax) then
        qr_count = qr_count + 1
      else
        non_qr_pcs[#non_qr_pcs + 1] = pc
        non_qr_idx[#non_qr_idx + 1] = i
      end
    end
  end
  if qr_count == 0 or #non_qr_pcs == 0 then
    return false
  end
  stdnse.debug1("Q/R AET reject suspected; retrying %d non-Q/R contexts without %d Q/R contexts",
    #non_qr_pcs, qr_count)
  local ok2, _, sub_results, sub_info =
    dicom.associate_extended(host, port, calling_ae, called_ae, non_qr_pcs, opts)
  if not ok2 then
    return false
  end
  pc_results = pc_results or {}
  for i, pc in ipairs(pcs) do
    pc_results[i] = pc_results[i] or {
      abstract_syntax = pc.abstract_syntax,
      transfer_syntaxes = pc.transfer_syntaxes,
    }
  end
  for k, orig_i in ipairs(non_qr_idx) do
    pc_results[orig_i] = sub_results[k]
  end
  if info then
    info.associations = info.associations + 1 + sub_info.associations
    info.associations_planned = info.associations
      + (sub_info.associations_planned - sub_info.associations)
    info.errors = sub_info.errors
  else
    sub_info.associations = 1 + sub_info.associations
    sub_info.associations_planned = 1 + sub_info.associations_planned
    info = sub_info
  end
  local rj = {
    source      = initial_err and initial_err.source or 1,
    reason      = initial_err and initial_err.reason or 3,
    reason_text = initial_err and initial_err.reason_text or "calling-AE-title-not-recognized",
    count       = qr_count,
  }
  return true, pc_results, info, rj
end

local VERIFICATION_CANARY = {
  { abstract_syntax = dicom.SOP_CLASS.VERIFICATION, transfer_syntaxes = TS_CMD },
}

local function merge_opts(base, extra)
  local out = {}
  for k, v in pairs(base or {}) do out[k] = v end
  for k, v in pairs(extra or {}) do out[k] = v end
  return out
end

-- Fragile embedded or legacy SCPs with small fixed PDU buffers (e.g. 4 KB) or
-- tight presentation-context ceilings may reset TCP, send A-ABORT, or send
-- A-ASSOCIATE-RJ (no-reason-given) on a multi-KB proposal. If a minimal
-- 1-context Verification canary succeeds, step down to "basic" in small
-- 4 KB / 16-PC batches so the device is still enumerated.
local function retry_fragile(host, port, calling_ae, called_ae, err, opts)
  local eligible
  if type(err) == "table" then
    eligible = (err.source == 1 or err.source == 2) and err.reason == 1
  else
    local s = tostring(err or "")
    eligible = (s:find("A%-ABORT") ~= nil) or (s:find("CONNECTION_RESET") ~= nil)
  end
  if not eligible then
    return false
  end
  local cok = dicom.associate_extended(host, port, calling_ae, called_ae,
    VERIFICATION_CANARY, opts)
  if not cok then
    return false
  end
  stdnse.debug1("Minimal Verification canary succeeded; stepping down to basic (4 KB / 16 PCs)")
  local bpcs, bentries = build_pcs("basic")
  local fopts = merge_opts(opts, { max_pcs = 16, max_rq_bytes = 4096 })
  local bok, berr, bresults, binfo =
    dicom.associate_extended(host, port, calling_ae, called_ae, bpcs, fopts)
  local qr_rj = nil
  if not bok and is_aet_reject(berr) then
    bok, bresults, binfo, qr_rj =
      retry_without_qr(host, port, calling_ae, called_ae, bpcs, nil, nil, berr, fopts)
  end
  if not bok then return false end
  binfo.associations = binfo.associations + 2 -- initial abort/reset/reject + canary
  binfo.associations_planned = binfo.associations_planned + 2
  return true, bpcs, bentries, bresults, binfo, qr_rj
end

action = function(host, port)
  local probe = (stdnse.get_script_args(SCRIPT_NAME .. ".probe") or "standard"):lower()
  if not PROBE_DEPTHS[probe] then
    stdnse.debug1("Unknown probe depth %q, using 'standard'", probe)
    probe = "standard"
  end
  local called_ae = stdnse.get_script_args(SCRIPT_NAME .. ".called_ae")
    or stdnse.get_script_args("dicom.called_aet")
  local calling_ae = stdnse.get_script_args(SCRIPT_NAME .. ".calling_ae")
    or stdnse.get_script_args("dicom.calling_aet")
  local timeout_s = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  if timeout_s and timeout_s <= 0 then timeout_s = nil end
  local max_pdu = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_pdu"))
  if max_pdu and max_pdu < 0 then max_pdu = nil end
  local base_opts = nil
  if timeout_s or max_pdu then
    base_opts = {
      timeout_ms = timeout_s and math.floor(timeout_s * 1000) or nil,
      max_pdu    = max_pdu and math.floor(max_pdu) or nil,
    }
  end

  local pcs, entries = build_pcs(probe)
  stdnse.debug1("probe=%s, proposing %d presentation contexts", probe, #pcs)

  local is_tls = dicom.tls_enabled(port)
  local active_opts = base_opts
  local ok, err, pc_results, info =
    dicom.associate_extended(host, port, calling_ae, called_ae, pcs, active_opts)
  local out = stdnse.output_table()
  local qr_aet_reject = nil
  local downgraded_from = nil

  if not ok then
    if is_aet_reject(err) then
      local recovered
      recovered, pc_results, info, qr_aet_reject =
        retry_without_qr(host, port, calling_ae, called_ae, pcs, nil, nil, err, active_opts)
      if recovered then ok = true end
    else
      local recovered, bpcs, bentries, bresults, binfo, brj =
        retry_fragile(host, port, calling_ae, called_ae, err, active_opts)
      if recovered then
        ok = true
        downgraded_from = probe
        probe, pcs, entries, pc_results, info, qr_aet_reject =
          "basic", bpcs, bentries, bresults, binfo, brj
      elseif type(err) ~= "table" and not is_tls and stdnse.get_script_args("dicom.tls") == nil then
        -- Auto-detect DICOM-over-TLS when run without -sV / dicom.tls=true
        -- and the peer rejected plaintext with a reset or TLS alert PDU.
        local es = tostring(err or "")
        if es:find("CONNECTION_RESET") or es:find("unexpected response PDU") then
          local tls_opts = merge_opts(base_opts, { tls = true })
          local tok, terr, tresults, tinfo =
            dicom.associate_extended(host, port, calling_ae, called_ae, pcs, tls_opts)
          if tok then
            ok, pc_results, info, is_tls, active_opts = true, tresults, tinfo, true, tls_opts
          elseif is_aet_reject(terr) then
            local trec, tr2, ti2, trj =
              retry_without_qr(host, port, calling_ae, called_ae, pcs, nil, nil, terr, tls_opts)
            if trec then
              ok, pc_results, info, qr_aet_reject, is_tls, active_opts =
                true, tr2, ti2, trj, true, tls_opts
            else
              err, is_tls, active_opts = terr, true, tls_opts
            end
          else
            -- Also support fragile 4 KB legacy SCPs fronted by TLS.
            local frec, fpcs, fentries, fresults, finfo, frj =
              retry_fragile(host, port, calling_ae, called_ae, terr, tls_opts)
            if frec then
              ok, is_tls, active_opts = true, true, tls_opts
              downgraded_from = probe
              probe, pcs, entries, pc_results, info, qr_aet_reject =
                "basic", fpcs, fentries, fresults, finfo, frj
            elseif type(terr) == "table" then
              err, is_tls, active_opts = terr, true, tls_opts
            end
          end
        end
      end
    end
  end

  -- Handle Q/R-gated AET rejects on follow-up batches (e.g. full probe batch 2
  -- over either plaintext or auto-detected TLS).
  if ok and info.errors then
    for _, msg in ipairs(info.errors) do
      if msg:find("AE%-title%-not%-recognized") then
        local rj = {
          source = 1,
          reason = msg:find("calling%-AE%-title%-not%-recognized") and 3 or 7,
          reason_text = msg:match("([%w-]+%-AE%-title%-not%-recognized)"),
        }
        local recovered, new_results, new_info, new_rj =
          retry_without_qr(host, port, calling_ae, called_ae, pcs, pc_results, info, rj, active_opts)
        if recovered then
          pc_results, info, qr_aet_reject = new_results, new_info, new_rj
        end
        break
      end
    end
  end

  if not ok then
    if type(err) ~= "table" then
      stdnse.debug1("Association failed: %s", err)
      if is_tls and is_likely_mtls_error(err) and is_expected_dicom_tls_port(port) then
        out.dicom    = "TLS endpoint detected, but DICOM association failed."
        out.tls_hint = "Server likely requires Mutual TLS (mTLS) with valid client certificates."
        out.error    = tostring(err or "")
        mark_dicom_service(host, port, true, false)
        return out
      end
      if not is_tls and tonumber(port.number) == 2762 then
        out.dicom    = "Possible DICOM/TLS endpoint (plaintext A-ASSOCIATE not accepted)"
        out.tls_hint = "Port 2762 is open, but DICOM associate could not be completed. Rerun with -sV or --script-args dicom.tls=true to confirm."
        out.error    = tostring(err or "")
        return out
      end
      return nil
    end
    out.dicom  = "DICOM Service Provider discovered!"
    out.config = string.format("Association rejected: %s / %s / %s",
      err.result_text or "?", err.source_text or "?", err.reason_text or "?")
    out.hint = REJECT_HINTS[err.source] and REJECT_HINTS[err.source][err.reason]
    mark_dicom_service(host, port, is_tls, true)
    return out
  end

  -- Implementation identification, for port.version and the association
  -- line. Calling --script on the CLI sets nmap.verbosity() == 1 even
  -- without -v, so > 1 is the user-requested verbose threshold (use -v
  -- with --script dicom-info, or -vv with -sC).
  local verbose = nmap.verbosity() > 1
  local _, vendor, clean_version, device_vendor =
    dicom.resolve_vendor_info(info.impl_version, info.impl_uid)
  if vendor then
    port.version.product = vendor
    if clean_version then port.version.version = clean_version end
  end
  if device_vendor then
    port.version.extrainfo = "Device: " .. device_vendor
  end
  mark_dicom_service(host, port, info.tls, true)

  local detail = {}
  if info.max_pdu then
    if info.max_pdu == 0 then
      detail[#detail + 1] = "max_pdu=0 (unlimited)"
    else
      detail[#detail + 1] = string.format("max_pdu=%d", info.max_pdu)
    end
  end
  if vendor then
    detail[#detail + 1] = "vendor=" .. vendor .. (clean_version and " " .. clean_version or "")
  end
  if device_vendor then
    detail[#detail + 1] = "device=" .. device_vendor
  end
  if info.impl_uid and (not vendor or verbose or device_vendor) then
    detail[#detail + 1] = "impl_uid=" .. info.impl_uid
  end
  if info.impl_version and (not vendor
      or (verbose and clean_version ~= info.impl_version)) then
    detail[#detail + 1] = "impl_version=" .. info.impl_version
  end
  out.association = #detail > 0
    and string.format("accepted (%s)", table.concat(detail, ", ")) or "accepted"

  local accepted, rejected, classes, commands, modalities = {}, {}, {}, {}, {}
  local accepted_ts_set, rejected_ts = {}, {}
  local sop_count, ts_probe_count = 0, 0
  local ct_supported, fallback_img_uid, fallback_storage_uid = false, nil, nil

  for i, r in ipairs(pc_results) do
    local entry = entries[i]
    if entry.is_ts_probe then
      ts_probe_count = ts_probe_count + 1
      local ts_label = dicom.TRANSFER_SYNTAX_NAMES[entry.ts_uid] or entry.ts_uid
      if r.result == 0 then
        accepted_ts_set[ts_label] = true
      elseif r.result ~= nil and r.result ~= 3 then
        rejected_ts[#rejected_ts + 1] = ts_label
      end
    else
      sop_count = sop_count + 1
      local name = entry.name
      if r.result == 0 then
        local ts_label = dicom.TRANSFER_SYNTAX_NAMES[r.accepted_ts]
          or r.accepted_ts or "(unknown TS)"
        accepted[#accepted + 1] = string.format("%s - %s", name, ts_label)
        if r.accepted_ts then accepted_ts_set[ts_label] = true end
        if r.abstract_syntax == dicom.SOP_CLASS.CT_IMAGE_STORAGE then
          ct_supported = true
        elseif entry.kind == "storage" then
          if not fallback_img_uid and MODALITY_BY_UID[r.abstract_syntax] then
            fallback_img_uid = r.abstract_syntax
          elseif not fallback_storage_uid then
            fallback_storage_uid = r.abstract_syntax
          end
        end
        local _, ops, _, class = classify(r.abstract_syntax)
        if class then classes[class] = true end
        for _, op in ipairs(ops or {}) do commands[op] = true end
        local modality = MODALITY_BY_UID[r.abstract_syntax]
        if modality then modalities[modality] = true end
      elseif r.result ~= nil then
        local code = dicom.PC_RESULT_NAMES[r.result] and r.result or "unknown"
        rejected[code] = rejected[code] or {}
        table.insert(rejected[code], name)
      end
    end
  end

  -- Rare fallback: if the SCP rejected CT Image Storage (e.g. an MRI-only or
  -- Ultrasound-only modality SCP) while accepting another Storage SOP class,
  -- run one small codec probe against that accepted Storage SOP class.
  local fb_uid = fallback_img_uid or fallback_storage_uid
  if probe ~= "basic" and not ct_supported and fb_uid then
    local ts_pcs = {}
    for _, ts_uid in ipairs(TS_STORAGE[probe]) do
      ts_pcs[#ts_pcs + 1] = {
        abstract_syntax   = fb_uid,
        transfer_syntaxes = { ts_uid },
      }
    end
    local fok, _, fresults, finfo =
      dicom.associate_extended(host, port, calling_ae, called_ae, ts_pcs, active_opts)
    if fok and fresults then
      info.associations = info.associations + finfo.associations
      info.associations_planned = info.associations_planned + finfo.associations_planned
      for k, fr in ipairs(fresults) do
        local ts_uid = TS_STORAGE[probe][k]
        local ts_label = dicom.TRANSFER_SYNTAX_NAMES[ts_uid] or ts_uid
        if fr.result == 0 then
          accepted_ts_set[ts_label] = true
        elseif fr.result ~= nil then
          rejected_ts[#rejected_ts + 1] = ts_label
        end
      end
    end
  end

  -- Probe depth and how it went out, so a "not probed" service, or a
  -- difference between two scans of one host, can be traced to the depth.
  local n = info.associations
  if info.errors then
    local answered = 0
    for _, r in ipairs(pc_results) do
      if r.result ~= nil then answered = answered + 1 end
    end
    out.probe = string.format("%s (%d of %d presentation contexts answered, %d of %d associations)",
      probe, answered, #pcs, n, info.associations_planned)
    out.warning = "results are partial: " .. table.concat(info.errors, "; ")
  else
    local dnote = downgraded_from
      and string.format(", auto-downgraded from %s for fragile SCP", downgraded_from) or ""
    local what = (ts_probe_count > 0)
      and string.format("%d SOP classes + %d transfer syntaxes proposed", sop_count, ts_probe_count)
      or string.format("%d SOP classes proposed", sop_count)
    out.probe = string.format("%s (%s, %d association%s%s)",
      probe, what, n, n == 1 and "" or "s", dnote)
  end

  if modalities["PET"] and modalities["CT"] then
    modalities["PET-CT"] = true
  end

  local services = summarize_services(pc_results, entries)
  local svc_out = stdnse.output_table()
  local has_services = false
  local qr_aet_arg = qr_aet_reject and (
    (qr_aet_reject.reason == 7) and "dicom.called_aet"
    or (qr_aet_reject.reason == 3) and "dicom.calling_aet"
    or "dicom.called_aet / dicom.calling_aet")
  for _, key in ipairs(SERVICE_KEYS) do
    local s = services[key]
    if qr_aet_reject and (key == "query" or key == "retrieve" or key == "modality_worklist") and not s then
      svc_out[key] = string.format("gated (%s - pass a recognized %s)",
        qr_aet_reject.reason_text or "AET rejected", qr_aet_arg)
      has_services = true
    elseif verbose or (s and s.accepted) then
      svc_out[key] = service_line(key, s)
      has_services = true
    end
  end
  if has_services then out.services = svc_out end
  if verbose then
    if next(classes) then out.service_classes = sorted_keys(classes) end
    if next(commands) then out.service_commands = sorted_keys(commands) end
  end
  if next(modalities) then out.modalities = sorted_keys(modalities) end
  out.inferred_device_class = device_class(classes)
  if next(accepted_ts_set) then
    out.transfer_syntaxes = sorted_keys(accepted_ts_set)
  end

  out.results = stdnse.output_table()
  if #accepted > 0 then
    local t = stdnse.output_table()
    t.count = #accepted
    if verbose or #accepted <= 10 then
      t.items = accepted
    else
      t.note = string.format("use -v to list all %d accepted contexts", #accepted)
    end
    out.results[dicom.PC_RESULT_NAMES[0]] = t
  end
  local rejected_summary = {}
  for _, code in ipairs(DEBUG_RESULT_ORDER) do
    local names = rejected[code]
    if names then
      rejected_summary[#rejected_summary + 1] = string.format("%d %s",
        #names, dicom.PC_RESULT_NAMES[code])
    end
  end
  if rejected.unknown then
    rejected_summary[#rejected_summary + 1] = string.format("%d unknown-result",
      #rejected.unknown)
  end
  if qr_aet_reject and qr_aet_reject.count and qr_aet_reject.count > 0 then
    rejected_summary[#rejected_summary + 1] = string.format(
      "%d %s (Q/R + MWL)",
      qr_aet_reject.count, qr_aet_reject.reason_text or "AET-rejected")
  end
  if #rejected_summary > 0 then
    out.results.rejected = rejected_summary
  end

  local security = stdnse.output_table()
  if info.tls then
    security.transport = "DICOM over TLS"
    if info.cert then security.certificate = cert_table(info.cert) end
  else
    security.transport = "plaintext (no TLS)"
  end
  local findings = security_findings(services, called_ae, info, qr_aet_reject)
  if #findings > 0 then security.findings = findings end
  out.security = security

  for _, code in ipairs(DEBUG_RESULT_ORDER) do
    local names = rejected[code]
    if names then
      stdnse.debug1("%s (%d): %s", dicom.PC_RESULT_NAMES[code], #names,
        table.concat(names, ", "))
    end
  end
  if rejected.unknown then
    stdnse.debug1("unknown-result (%d): %s", #rejected.unknown,
      table.concat(rejected.unknown, ", "))
  end
  if #rejected_ts > 0 then
    stdnse.debug1("transfer-syntaxes-not-supported (%d codecs): %s",
      #rejected_ts, table.concat(rejected_ts, ", "))
  end

  return out
end
