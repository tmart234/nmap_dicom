--[[
Enumerates the SOP classes and transfer syntaxes a DICOM Service Provider
accepts by proposing a curated set of presentation contexts in a single
A-ASSOCIATE request and parsing the per-PC result map returned in the
A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2).

Each presentation context is reported as one of:
  accepted (0), user-rejection (1), no-reason (2),
  abstract-syntax-not-supported (3), transfer-syntaxes-not-supported (4)

Only the "accepted" bucket is rendered in normal script output — that is
the SCP's positive capability surface. The other four buckets are emitted
at debug level only (-d), since "everything we proposed that this SCP
doesn't serve" is useful for triage but noise in default output.

This is a capability fingerprint: it identifies which Storage SOP classes
the SCP serves (CT/MR/US/CR/DX/Mammo/PET/NM/XA/XRF/Endoscopy/RT/SR/ECG/
Ophthalmic/Whole-Slide/...), whether it supports Modality Worklist FIND,
Patient/Study Root Query/Retrieve, Storage Commitment, MPPS, UPS, and Print
Management, and which transfer syntaxes it negotiates.

Ubiquity: every presentation context is proposed with Implicit VR Little
Endian (the one transfer syntax every conformant SCP must support, PS3.5
§10.1), so even the oldest modalities negotiate at least one context. Three
probe depths trade breadth against A-ASSOCIATE-RQ size:
  basic    - core SOP classes, Implicit+Explicit VR only (smallest PDU;
             best for fragile/embedded legacy devices)
  standard - core SOP classes with the commonly-negotiated transfer-syntax
             set (default)
  full     - core + long-tail SOP classes (Multi-frame SC, RT, extended SR,
             UPS, ophthalmic, waveform, segmentation, whole-slide, ...) with
             the complete transfer-syntax matrix

From the accepted SOP classes the script also derives:
  modalities         - the imaging modalities implied by accepted Storage
                       SOP classes (CT, MRI, Ultrasound, Mammography,
                       X-Ray, X-Ray Angiography, Fluoroscopy, PET, PET-CT,
                       Nuclear Medicine, Endoscopy, ECG, Ophthalmic,
                       Whole Slide Imaging, ...). PET-CT is reported when
                       both PET and CT are accepted.
  service_commands   - the DIMSE commands implied by the accepted SOP
                       classes: C-ECHO (Verification), C-STORE (Storage),
                       C-FIND (Q/R FIND or Modality Worklist FIND),
                       C-MOVE (Q/R MOVE), C-GET (Q/R GET).
  inferred_device_class - PACS/VNA, Modality, RIS gateway, Archive
                       front-end, or Print server. This taxonomy is a
                       practitioner consensus, not a normative DICOM
                       concept; treat it as a fingerprint, not a
                       classification.
  security           - transport (plaintext vs DICOM-over-TLS), the TLS peer
                       certificate when present, and findings derived purely
                       from what the single association already revealed
                       (unauthenticated access, Query/Retrieve exfiltration
                       surface, unauthenticated C-STORE surface, plaintext
                       PHI, weak/mismatched TLS certificate, absent mutual
                       TLS). No DIMSE commands or patient data are ever sent.

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
-- @usage nmap -p 2762 --script dicom-enum --script-args dicom.tls=true <target>
-- @usage nmap --script dicom-enum --script-args dicom-enum.probe=full <target>
-- @usage nmap --script dicom-enum --script-args dicom-enum.ports=11114,11115 <target>
--
-- @args dicom.called_aet     Called AET. Default: ANY-SCP
-- @args dicom.calling_aet    Calling AET. Default: ECHOSCU
-- @args dicom.timeout_ms     Socket timeout in ms. Default: 3000
-- @args dicom.tls            Transport override: "true" forces DICOM-over-TLS,
--                            "false" forces plaintext. Default: unset (adapt
--                            to Nmap's own -sV SSL/TLS service detection).
-- @args dicom.no_release     If set, the script omits A-RELEASE-RQ and lets
--                            the SCP see an aborted association. Default:
--                            unset (release is sent).
-- @args dicom-enum.probe     Probe depth: "basic", "standard" (default), or
--                            "full". See the description for the trade-off.
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
-- |         MR Image Storage - JPEG 2000 Image Compression (Lossless Only)
-- |   security:
-- |     transport: plaintext (no TLS)
-- |     findings:
-- |       Any called-AET accepted — no AE-title allowlist enforced
-- |       Query/Retrieve C-MOVE accepted — bulk retrieval to an arbitrary AE
-- |       15 Storage SOP classes accepted — unauthenticated C-STORE surface
-- |_      Plaintext transport — associations and PHI exposed on the wire
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
-- <table key="security">
--   <elem key="transport">plaintext (no TLS)</elem>
--   <table key="findings">
--     <elem>Any called-AET accepted — no AE-title allowlist enforced</elem>
--   </table>
-- </table>
---

author     = "Tyler M <tmart234()gmail.com>, Paulino Calderon <paulino()calderonpale.com>"
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

local TS_I       = "1.2.840.10008.1.2"        -- Implicit VR LE  (mandatory)
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

-- Storage transfer-syntax sets, chosen per probe depth. Implicit VR LE is
-- always first so that even an SCP that negotiates nothing else still
-- accepts the context (PS3.5 §10.1 makes Implicit VR LE mandatory).
--
--   basic    - Implicit + Explicit VR only; smallest A-ASSOCIATE-RQ, best
--              for fragile/embedded legacy devices that choke on large PDUs.
--   standard - the transfer syntaxes a SCP realistically negotiates in the
--              field; moderate PDU size (default).
--   full     - the complete matrix, for exhaustive codec fingerprinting of
--              modern devices.
local TS_STORAGE_BASIC    = { TS_I, TS_E }
local TS_STORAGE_STANDARD = {
  TS_I, TS_E, TS_DEFLATE, TS_JPEG_BL, TS_JPEG_LL, TS_J2K_LL, TS_J2K, TS_RLE,
}
local TS_STORAGE_FULL = {
  TS_I, TS_E, TS_EBE, TS_DEFLATE,
  TS_JPEG_BL, TS_JPEG_LL, TS_JLS_LL,
  TS_J2K_LL, TS_J2K, TS_RLE,
  TS_HTJ2K_L, TS_HTJ2K_R, TS_HTJ2K,
}

-- Non-storage classes (Verification, Q/R, MWL, MPPS, StgCmt, UPS, Print) do
-- not benefit from compressed transfer syntaxes; keep the proposal minimal.
local CMD_TS = { TS_I, TS_E }

-- ---------- Master presentation-context catalogue ----------
-- kind  = "storage" (gets the depth-selected storage TS set) or "cmd"
--         (always CMD_TS).
-- depth = "core" (proposed at every depth) or "ext" (proposed only in
--         "full"). The "core" set is the broadly-supported capability
--         surface; "ext" is the long tail that matters for exhaustive
--         fingerprinting of modern systems.
local PC_MASTER = {
  -- Verification
  {name = "Verification",                                uid = "1.2.840.10008.1.1",                   kind = "cmd",     depth = "core"},

  -- Storage SOP classes (core)
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

  -- Storage SOP classes (extended / long tail — full probe only)
  {name = "Multi-frame Single Bit SC Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.7.1",         kind = "storage", depth = "ext"},
  {name = "Multi-frame Grayscale Byte SC Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.2",         kind = "storage", depth = "ext"},
  {name = "Multi-frame Grayscale Word SC Image Storage", uid = "1.2.840.10008.5.1.4.1.1.7.3",         kind = "storage", depth = "ext"},
  {name = "Multi-frame True Color SC Image Storage",     uid = "1.2.840.10008.5.1.4.1.1.7.4",         kind = "storage", depth = "ext"},
  {name = "Enhanced SR Storage",                         uid = "1.2.840.10008.5.1.4.1.1.88.22",       kind = "storage", depth = "ext"},
  {name = "Comprehensive 3D SR Storage",                 uid = "1.2.840.10008.5.1.4.1.1.88.34",       kind = "storage", depth = "ext"},
  {name = "Key Object Selection Document Storage",       uid = "1.2.840.10008.5.1.4.1.1.88.59",       kind = "storage", depth = "ext"},
  {name = "Color Softcopy Presentation State Storage",   uid = "1.2.840.10008.5.1.4.1.1.11.2",        kind = "storage", depth = "ext"},
  {name = "Segmentation Storage",                        uid = "1.2.840.10008.5.1.4.1.1.66.4",        kind = "storage", depth = "ext"},
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
  {name = "RT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.481.1",       kind = "storage", depth = "ext"},
  {name = "RT Dose Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.2",       kind = "storage", depth = "ext"},
  {name = "RT Structure Set Storage",                    uid = "1.2.840.10008.5.1.4.1.1.481.3",       kind = "storage", depth = "ext"},
  {name = "RT Plan Storage",                             uid = "1.2.840.10008.5.1.4.1.1.481.5",       kind = "storage", depth = "ext"},
  {name = "RT Ion Plan Storage",                         uid = "1.2.840.10008.5.1.4.1.1.481.8",       kind = "storage", depth = "ext"},
  {name = "Encapsulated CDA Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.2",       kind = "storage", depth = "ext"},
  {name = "Encapsulated STL Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.3",       kind = "storage", depth = "ext"},
  {name = "Surface Scan Mesh Storage",                   uid = "1.2.840.10008.5.1.4.1.1.68.1",        kind = "storage", depth = "ext"},

  -- Worklist + Query/Retrieve (core)
  {name = "Modality Worklist Information Model - FIND",  uid = "1.2.840.10008.5.1.4.31",              kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - FIND",          uid = "1.2.840.10008.5.1.4.1.2.1.1",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - MOVE",          uid = "1.2.840.10008.5.1.4.1.2.1.2",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - GET",           uid = "1.2.840.10008.5.1.4.1.2.1.3",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - FIND",            uid = "1.2.840.10008.5.1.4.1.2.2.1",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - MOVE",            uid = "1.2.840.10008.5.1.4.1.2.2.2",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - GET",             uid = "1.2.840.10008.5.1.4.1.2.2.3",         kind = "cmd",     depth = "core"},

  -- Workflow (core)
  {name = "Storage Commitment Push Model",               uid = "1.2.840.10008.1.20.1",                kind = "cmd",     depth = "core"},
  {name = "Modality Performed Procedure Step",           uid = "1.2.840.10008.3.1.2.3.3",             kind = "cmd",     depth = "core"},

  -- Workflow (extended / full probe only)
  {name = "Unified Procedure Step - Push",               uid = "1.2.840.10008.5.1.4.34.6.1",          kind = "cmd",     depth = "ext"},
  {name = "Unified Procedure Step - Watch",              uid = "1.2.840.10008.5.1.4.34.6.2",          kind = "cmd",     depth = "ext"},

  -- Print (core)
  {name = "Basic Grayscale Print Management Meta",       uid = "1.2.840.10008.5.1.1.9",               kind = "cmd",     depth = "core"},
}

-- Build the list of presentation contexts (and the parallel metadata list)
-- for the requested probe depth.
local function storage_ts_for_depth(depth)
  if depth == "basic" then return TS_STORAGE_BASIC end
  if depth == "full"  then return TS_STORAGE_FULL  end
  return TS_STORAGE_STANDARD
end

local function build_pcs(depth)
  local want_ext   = (depth == "full")
  local storage_ts = storage_ts_for_depth(depth)
  local pcs, meta = {}, {}
  for _, e in ipairs(PC_MASTER) do
    if e.depth == "core" or want_ext then
      local ts = (e.kind == "storage") and storage_ts or CMD_TS
      pcs[#pcs + 1]  = { abstract_syntax = e.uid, transfer_syntaxes = ts }
      meta[#meta + 1] = e
    end
  end
  return pcs, meta
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

local VALID_PROBES = { basic = true, standard = true, full = true }

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

-- Format a certificate validity date, which Nmap may hand back as a string
-- or as a broken-out date table.
local function fmt_cert_date(d)
  if type(d) == "table" then
    if d.year then
      return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        d.year or 0, d.month or 0, d.day or 0,
        d.hour or 0, d.min or 0, d.sec or 0)
    end
    return "?"
  end
  return tostring(d)
end

-- Summarise a TLS certificate as an ordered output table.
local function cert_table(cert)
  local t = stdnse.output_table()
  t.subject = cert.subject and cert.subject.commonName or "?"
  t.issuer  = cert.issuer  and cert.issuer.commonName  or "?"
  if cert.validity and cert.validity.notAfter then
    t.not_after = fmt_cert_date(cert.validity.notAfter)
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

-- Weak-crypto / trust warnings derived from a TLS certificate.
local function cert_findings(cert, out)
  if cert.pubkey and cert.pubkey.type == "rsa" and cert.pubkey.bits
     and cert.pubkey.bits < 2048 then
    out[#out + 1] = "TLS certificate uses a weak RSA key (< 2048-bit)"
  end
  if cert.sig_algorithm then
    local low = tostring(cert.sig_algorithm):lower()
    if low:find("sha1") or low:find("md5") then
      out[#out + 1] = "TLS certificate uses a weak signature algorithm (SHA-1/MD5)"
    end
  end
  local subj = cert.subject and cert.subject.commonName
  local iss  = cert.issuer  and cert.issuer.commonName
  if subj and iss and subj == iss then
    out[#out + 1] = "TLS certificate is self-signed (no CA trust chain)"
  end
end

-- Count how many accepted abstract syntaxes are Storage SOP classes, and
-- which Query/Retrieve DIMSE operations (FIND/MOVE/GET) were accepted.
local QR_PREFIX = "1.2.840.10008.5.1.4.1.2."
local STORAGE_PREFIX = "1.2.840.10008.5.1.4.1.1."

local function security_findings(accepted_uids, called_aet, info)
  local findings = {}

  -- Unauthenticated association: we proposed a default/empty called-AET and
  -- the SCP still accepted, so it enforces no AE-title allowlist.
  if not called_aet or called_aet == "" or called_aet == "ANY-SCP" then
    findings[#findings + 1] = "Any called-AET accepted — no AE-title allowlist enforced"
  end

  -- Query/Retrieve exfiltration surface.
  local has_find, has_move, has_get = false, false, false
  local storage_count = 0
  for _, uid in ipairs(accepted_uids) do
    if uid:sub(1, #QR_PREFIX) == QR_PREFIX then
      local tail = uid:match("%.([123])$")
      if     tail == "1" then has_find = true
      elseif tail == "2" then has_move = true
      elseif tail == "3" then has_get  = true
      end
    elseif uid:sub(1, #STORAGE_PREFIX) == STORAGE_PREFIX then
      storage_count = storage_count + 1
    end
  end
  if has_find then
    findings[#findings + 1] = "Query/Retrieve C-FIND accepted — patient/study metadata enumeration possible (dicom-brute, then a C-FIND client)"
  end
  if has_move then
    findings[#findings + 1] = "Query/Retrieve C-MOVE accepted — bulk image retrieval to an arbitrary destination AE possible"
  end
  if has_get then
    findings[#findings + 1] = "Query/Retrieve C-GET accepted — direct image retrieval possible"
  end
  if storage_count > 0 then
    findings[#findings + 1] = string.format(
      "%d Storage SOP class%s accepted — unauthenticated C-STORE (data/malware injection) surface",
      storage_count, storage_count == 1 and "" or "es")
  end

  -- Transport.
  if info and info.tls then
    findings[#findings + 1] =
      "TLS server did not request a client certificate — no mutual TLS / IHE ATNA node authentication"
    if info.cert then cert_findings(info.cert, findings) end
  else
    findings[#findings + 1] =
      "Plaintext transport — associations and PHI exposed on the wire (consider DICOM-over-TLS, PS3.15 §B)"
  end

  return findings
end

-- ---------- action ----------

action = function(host, port)
  local out = stdnse.output_table()

  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  local calling_aet = stdnse.get_script_args("dicom.calling_aet")

  local probe = (stdnse.get_script_args("dicom-enum.probe") or "standard"):lower()
  if not VALID_PROBES[probe] then
    stdnse.debug1("DICOM: unknown probe depth %q, falling back to 'standard'", probe)
    probe = "standard"
  end

  local pcs, pcmeta = build_pcs(probe)
  stdnse.debug1("DICOM: probe=%s, proposing %d presentation contexts", probe, #pcs)

  local ok, err, pc_results, info =
    dicom.associate_extended(host, port, calling_aet, called_aet, pcs)

  if not ok then
    if type(err) == "table" and err.err == "ASSOCIATE REJECT received" then
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
      mark_dicom_service(host, port)
      return out
    end
    local e = tostring(err or "")
    out.dicom = "DICOM Service Provider discovered!"
    out.error = e
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

  -- Bucket per-PC results and collect accepted service classes / UIDs.
  local buckets = { [0]={}, [1]={}, [2]={}, [3]={}, [4]={}, unknown={} }
  local accepted_services = {}
  local accepted_uids = {}
  for i, r in ipairs(pc_results) do
    local pc = pcmeta[i]
    local code = r.result
    if code == 0 then
      table.insert(buckets[0], string.format("%s - %s", pc.name, ts_label(r.accepted_ts)))
      accepted_uids[#accepted_uids + 1] = r.abstract_syntax
      local svc = dicom.service_class_for_uid(r.abstract_syntax)
      if svc then accepted_services[svc] = true end
    elseif code == 1 or code == 2 or code == 3 or code == 4 then
      table.insert(buckets[code], pc.name)
    else
      table.insert(buckets.unknown, pc.name)
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

  -- Security assessment, derived entirely from the single association above
  -- (no DIMSE commands or patient data sent).
  local security = stdnse.output_table()
  if info and info.tls then
    security.transport = "DICOM over TLS"
    if info.cert then
      security.certificate = cert_table(info.cert)
    end
  else
    security.transport = "plaintext (no TLS)"
  end
  local findings = security_findings(accepted_uids, called_aet, info)
  if #findings > 0 then
    security.findings = findings
  end
  out.security = security

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
