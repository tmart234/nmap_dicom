local datetime = require "datetime"
local dicom = require "dicom"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates the SOP classes and transfer syntaxes a DICOM Service Provider
(SCP) accepts, by proposing a curated set of presentation contexts in an
A-ASSOCIATE request and reading the per-context result map in the
A-ASSOCIATE-AC (PS3.8 section 9.3.3.2).

No DIMSE messages or patient data are sent, and the whole catalogue goes out
in one association (two for the "full" probe at the default limits), so the
script holds at most one slot of the SCP's association pool at a time. This
is the main difference from dicom-info, which sends a C-ECHO and spends a
separate association on each transfer syntax it tests.

From the accepted contexts the script reports:
  services          one line per PS3.4 Service Class (verification,
                    storage, query, retrieve, modality_worklist,
                    storage_commitment, mpps, ups, print): "yes" with the
                    negotiated DIMSE operations and the Q/R information
                    models or UPS / Print SOP classes behind them, "no" when
                    every proposed context was rejected, or "not probed"
                    when this probe depth proposed none. C-FIND is
                    attributed to query or modality_worklist by the
                    information model it runs against.
  service_classes   the accepted Service Classes, with Query/Retrieve named
                    by information model (QR-Patient-Root, QR-Study-Root,
                    QR-Patient-Study).
  service_commands  the DIMSE-C and DIMSE-N operations those SOP classes
                    carry.
  modalities        the imaging modalities implied by the accepted Storage
                    SOP classes. PET-CT is reported when both PET and CT are
                    accepted.
  inferred_device_class
                    PACS/VNA, Modality, RIS gateway, Archive front-end or
                    Print server. This is a practitioner taxonomy, not a
                    DICOM concept; treat it as a fingerprint.
  results           each accepted context with the transfer syntax the SCP
                    chose for it. Rejected contexts (user-rejection,
                    no-reason, abstract-syntax-not-supported,
                    transfer-syntaxes-not-supported) are listed at debug
                    level (-d).
  security          the transport, the TLS certificate when there is one,
                    and findings drawn from the association alone: no
                    AE-title allowlist, Query/Retrieve and C-STORE exposure,
                    plaintext transport, a weak or self-signed certificate,
                    and no mutual TLS.

An accepted context means the SCP will accept requests for that SOP class,
not that an operation will succeed: destination AE allowlists, storage
policy and DIMSE-level refusals are separate layers. Each accepted context
also carries only the one transfer syntax the SCP chose from those proposed;
the others are neither accepted nor rejected. Scripts such as dicom-cfind-ls,
dicom-cmove, dicom-get and dicom-store-inject test the operations
themselves.

Every context is proposed with Implicit VR Little Endian, the transfer
syntax every SCP must support (PS3.5 section 10.1), so even old devices
negotiate. The dicom-enum.probe argument trades breadth against
A-ASSOCIATE-RQ size:
  basic     core SOP classes, Implicit and Explicit VR only (about 3 KB;
            for fragile or embedded legacy devices)
  standard  core SOP classes with the commonly negotiated compressed
            transfer syntaxes (about 7 KB; the default)
  full      core and long-tail SOP classes (multi-frame SC, RT, extended SR,
            UPS, ophthalmic, waveform, segmentation, whole-slide, ...) with
            every transfer syntax (about 21 KB, split across two
            associations at the default dicom.max_pcs / dicom.max_rq_bytes)
The probe line records the depth, the contexts proposed and the
associations used, so a "not probed" service or a difference between two
scans can be traced to the depth.

The script does not guess Application Entity Titles. If the SCP enforces an
AE-title allowlist it rejects the association and the script reports the
reason; find a valid title with dicom-brute and pass it with
dicom.called_aet or dicom.calling_aet.
]]

---
-- @usage nmap -p 104,4242,11112 --script dicom-enum <target>
-- @usage nmap -sV --script dicom-enum --script-args dicom-enum.probe=full <target>
-- @usage nmap -p 11112 --script dicom-enum --script-args dicom.called_aet=ORTHANC <target>
-- @usage nmap -p 2762 --script dicom-enum --script-args dicom.tls=true <target>
-- @usage nmap --script dicom-enum --script-args dicom-enum.ports=11114 <target>
--
-- @args dicom-enum.probe Probe depth: "basic", "standard" or "full" (see the
--                        description). Default: standard
-- @args dicom-enum.ports Optional comma-separated list of extra ports to run
--                        on, e.g. "104,11112,2762,4242", for SCPs on
--                        non-standard ports that -sV does not identify as
--                        DICOM.
--
-- @output
-- PORT      STATE SERVICE
-- 11112/tcp open  dicom
-- | dicom-enum:
-- |   association: accepted (max_pdu=16382, vendor=pynetdicom)
-- |   probe: standard (36 presentation contexts proposed, 1 association)
-- |   services:
-- |     verification: yes - C-ECHO
-- |     storage: yes - C-STORE (25 SOP classes)
-- |     query: yes - C-FIND (Patient Root, Study Root)
-- |     retrieve: yes - C-GET, C-MOVE (Patient Root, Study Root)
-- |     modality_worklist: yes - C-FIND
-- |     storage_commitment: no
-- |     mpps: no
-- |     ups: not probed
-- |     print: no
-- |   service_classes:
-- |     Modality-Worklist
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
-- |     PET
-- |     PET-CT
-- |     Ultrasound
-- |   inferred_device_class: PACS/VNA
-- |   results:
-- |     accepted:
-- |       count: 33
-- |       items:
-- |         Verification - Implicit VR Little Endian
-- |         CT Image Storage - Implicit VR Little Endian
-- |         MR Image Storage - Implicit VR Little Endian
-- |   security:
-- |     transport: plaintext (no TLS)
-- |     findings:
-- |       Any called-AET accepted - no AE-title allowlist enforced
-- |       Query/Retrieve C-FIND accepted - patient/study metadata enumeration possible
-- |       Query/Retrieve C-MOVE accepted - bulk image retrieval to an arbitrary destination AE possible
-- |       Query/Retrieve C-GET accepted - direct image retrieval possible
-- |       25 Storage SOP classes accepted - unauthenticated C-STORE (data/malware injection) surface
-- |_      Plaintext transport - associations and PHI exposed on the wire (consider DICOM-over-TLS, PS3.15 Annex B)
--
-- @output
-- PORT      STATE SERVICE
-- 11112/tcp open  dicom
-- | dicom-enum:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Association rejected: rejected-permanent / DICOM-UL-service-user / called-AE-title-not-recognized
-- |_  hint: Called-AET not recognized - try dicom.called_aet=<AET>
--
-- @xmloutput
-- <elem key="association">accepted (max_pdu=16382, vendor=pynetdicom)</elem>
-- <elem key="probe">standard (36 presentation contexts proposed, 1 association)</elem>
-- <table key="services">
--   <elem key="verification">yes - C-ECHO</elem>
--   <elem key="storage">yes - C-STORE (25 SOP classes)</elem>
--   <elem key="query">yes - C-FIND (Patient Root, Study Root)</elem>
--   <elem key="retrieve">yes - C-GET, C-MOVE (Patient Root, Study Root)</elem>
--   <elem key="modality_worklist">yes - C-FIND</elem>
--   <elem key="storage_commitment">no</elem>
--   <elem key="mpps">no</elem>
--   <elem key="ups">not probed</elem>
--   <elem key="print">no</elem>
-- </table>
-- <table key="service_classes">
--   <elem>Modality-Worklist</elem>
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
-- </table>
-- <elem key="inferred_device_class">PACS/VNA</elem>
-- <table key="results">
--   <table key="accepted">
--     <elem key="count">33</elem>
--     <table key="items">
--       <elem>Verification - Implicit VR Little Endian</elem>
--     </table>
--   </table>
-- </table>
-- <table key="security">
--   <elem key="transport">plaintext (no TLS)</elem>
--   <table key="findings">
--     <elem>Any called-AET accepted - no AE-title allowlist enforced</elem>
--   </table>
-- </table>
---

author = {
  "Tyler M <tmart234()gmail.com>",
  "Paulino Calderon <paulino()calderonpale.com>",
  "Nichelle Gilbert <nich.gilbert()gmail.com>",
}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local COMMON_DICOM_PORTS = {104, 2761, 2762, 4242, 11112}

-- Parse a comma/space separated port list into a lookup set.
local function parse_ports_arg(s)
  if not s then return nil end
  local set = {}
  for n in string.gmatch(s, "%d+") do
    set[tonumber(n)] = true
  end
  return next(set) and set or nil
end

local custom_ports = parse_ports_arg(stdnse.get_script_args(SCRIPT_NAME .. ".ports"))

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  if custom_ports and custom_ports[port.number] then return true end
  return shortport.port_or_service(COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp")(host, port)
end

-- ---------- Presentation context catalogue ----------

local TS = dicom.TRANSFER_SYNTAX

-- Storage transfer syntax sets, chosen per probe depth. Implicit VR LE comes
-- first so that even an SCP that negotiates nothing else accepts the
-- context.
local TS_STORAGE = {
  basic = { TS.IMPLICIT_LE, TS.EXPLICIT_LE },
  standard = {
    TS.IMPLICIT_LE, TS.EXPLICIT_LE, TS.DEFLATED_LE, TS.JPEG_BASELINE,
    TS.JPEG_LOSSLESS, TS.JPEG2000_LOSSLESS, TS.JPEG2000, TS.RLE,
  },
  full = {
    TS.IMPLICIT_LE, TS.EXPLICIT_LE, TS.EXPLICIT_BE, TS.DEFLATED_LE,
    TS.JPEG_BASELINE, TS.JPEG_LOSSLESS, TS.JPEG_LS,
    TS.JPEG2000_LOSSLESS, TS.JPEG2000, TS.RLE,
    TS.HTJ2K_LOSSLESS, TS.HTJ2K_LOSSLESS_RPCL, TS.HTJ2K,
  },
}

-- Non-storage classes (Verification, Q/R, MWL, MPPS, Storage Commitment,
-- UPS, Print) gain nothing from compressed transfer syntaxes.
local TS_CMD = { TS.IMPLICIT_LE, TS.EXPLICIT_LE }

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

  -- Worklist and Query/Retrieve
  {name = "Modality Worklist Information Model - FIND",  uid = "1.2.840.10008.5.1.4.31",              kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - FIND",          uid = "1.2.840.10008.5.1.4.1.2.1.1",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - MOVE",          uid = "1.2.840.10008.5.1.4.1.2.1.2",         kind = "cmd",     depth = "core"},
  {name = "Patient Root Query/Retrieve - GET",           uid = "1.2.840.10008.5.1.4.1.2.1.3",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - FIND",            uid = "1.2.840.10008.5.1.4.1.2.2.1",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - MOVE",            uid = "1.2.840.10008.5.1.4.1.2.2.2",         kind = "cmd",     depth = "core"},
  {name = "Study Root Query/Retrieve - GET",             uid = "1.2.840.10008.5.1.4.1.2.2.3",         kind = "cmd",     depth = "core"},

  -- Workflow
  {name = "Storage Commitment Push Model",               uid = "1.2.840.10008.1.20.1",                kind = "cmd",     depth = "core"},
  {name = "Modality Performed Procedure Step",           uid = "1.2.840.10008.3.1.2.3.3",             kind = "cmd",     depth = "core"},
  {name = "Unified Procedure Step - Push",               uid = "1.2.840.10008.5.1.4.34.6.1",          kind = "cmd",     depth = "ext"},
  {name = "Unified Procedure Step - Watch",              uid = "1.2.840.10008.5.1.4.34.6.2",          kind = "cmd",     depth = "ext"},

  -- Print
  {name = "Basic Grayscale Print Management Meta",       uid = "1.2.840.10008.5.1.1.9",               kind = "cmd",     depth = "core"},
}

-- Build the presentation contexts for a probe depth, plus the parallel list
-- of catalogue entries they came from.
local function build_pcs(depth)
  local pcs, entries = {}, {}
  for _, e in ipairs(CATALOGUE) do
    if e.depth == "core" or depth == "full" then
      local ts = (e.kind == "storage") and TS_STORAGE[depth] or TS_CMD
      pcs[#pcs + 1] = { abstract_syntax = e.uid, transfer_syntaxes = ts }
      entries[#entries + 1] = e
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
  ["1.2.840.10008.5.1.4.1.1.3.1"]      = "Ultrasound",
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
  ["1.2.840.10008.5.1.4.1.1.481.1"]    = "RT Image",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.1"] = "Ophthalmic Photography",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.2"] = "Ophthalmic Photography",
  ["1.2.840.10008.5.1.4.1.1.77.1.5.4"] = "Ophthalmic Tomography (OCT)",
  ["1.2.840.10008.5.1.4.1.1.9.1.1"]    = "ECG (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.9.1.2"]    = "ECG (Waveform)",
  ["1.2.840.10008.5.1.4.1.1.9.1.3"]    = "ECG (Waveform)",
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
local function summarize_services(pc_results)
  local out = {}
  for _, r in ipairs(pc_results) do
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

-- Weak-crypto and trust warnings derived from a TLS certificate.
local function cert_findings(cert, out)
  if cert.pubkey and cert.pubkey.type == "rsa" and cert.pubkey.bits
     and cert.pubkey.bits < 2048 then
    out[#out + 1] = "TLS certificate uses a weak RSA key (< 2048-bit)"
  end
  if cert.sig_algorithm then
    local low = tostring(cert.sig_algorithm):lower()
    if low:find("sha1", 1, true) or low:find("md5", 1, true) then
      out[#out + 1] = "TLS certificate uses a weak signature algorithm (SHA-1/MD5)"
    end
  end
  local subj = cert.subject and cert.subject.commonName
  local iss  = cert.issuer  and cert.issuer.commonName
  if subj and iss and subj == iss then
    out[#out + 1] = "TLS certificate is self-signed (no CA trust chain)"
  end
end

-- Findings drawn from the association alone; no DIMSE messages are sent.
local function security_findings(services, called_aet, info)
  local findings = {}

  -- The default called AET was accepted, so no AE-title allowlist applies.
  if not called_aet or called_aet == "" or called_aet == "ANY-SCP" then
    findings[#findings + 1] = "Any called-AET accepted - no AE-title allowlist enforced"
  end

  local query, retrieve, storage = services.query, services.retrieve, services.storage
  if query and query.accepted then
    findings[#findings + 1] = "Query/Retrieve C-FIND accepted - patient/study metadata enumeration possible"
  end
  if retrieve and retrieve.ops["C-MOVE"] then
    findings[#findings + 1] = "Query/Retrieve C-MOVE accepted - bulk image retrieval to an arbitrary destination AE possible"
  end
  if retrieve and retrieve.ops["C-GET"] then
    findings[#findings + 1] = "Query/Retrieve C-GET accepted - direct image retrieval possible"
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

local function mark_dicom_service(host, port)
  port.version.name = dicom.tls_enabled(port) and "dicom-tls" or "dicom"
  nmap.set_port_version(host, port)
end

action = function(host, port)
  local probe = (stdnse.get_script_args(SCRIPT_NAME .. ".probe") or "standard"):lower()
  if not PROBE_DEPTHS[probe] then
    stdnse.debug1("Unknown probe depth %q, using 'standard'", probe)
    probe = "standard"
  end
  local pcs, entries = build_pcs(probe)
  stdnse.debug1("probe=%s, proposing %d presentation contexts", probe, #pcs)

  local ok, err, pc_results, info = dicom.associate_extended(host, port, nil, nil, pcs)
  local out = stdnse.output_table()

  if not ok then
    if type(err) ~= "table" then
      stdnse.debug1("Association failed: %s", err)
      return nil
    end
    out.dicom  = "DICOM Service Provider discovered!"
    out.config = string.format("Association rejected: %s / %s / %s",
      err.result_text or "?", err.source_text or "?", err.reason_text or "?")
    out.hint = REJECT_HINTS[err.source] and REJECT_HINTS[err.source][err.reason]
    mark_dicom_service(host, port)
    return out
  end

  -- Implementation identification, for port.version and the association
  -- line.
  local version, vendor, _, device_vendor =
    dicom.resolve_vendor_info(info.impl_version, info.impl_uid)
  local has_version = version and version ~= info.impl_version
  if vendor then
    port.version.product = vendor
    if has_version then port.version.version = version end
  end
  if device_vendor then
    port.version.extrainfo = "Device: " .. device_vendor
  end
  mark_dicom_service(host, port)

  local detail = {}
  if info.max_pdu then
    detail[#detail + 1] = string.format("max_pdu=%d", info.max_pdu)
  end
  if vendor then
    detail[#detail + 1] = "vendor=" .. vendor .. (has_version and " " .. version or "")
  end
  if device_vendor then
    detail[#detail + 1] = "device=" .. device_vendor
  end
  out.association = #detail > 0
    and string.format("accepted (%s)", table.concat(detail, ", ")) or "accepted"

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
    out.probe = string.format("%s (%d presentation contexts proposed, %d association%s)",
      probe, #pcs, n, n == 1 and "" or "s")
  end

  local accepted, rejected, classes, commands, modalities = {}, {}, {}, {}, {}
  for i, r in ipairs(pc_results) do
    local name = entries[i].name
    if r.result == 0 then
      accepted[#accepted + 1] = string.format("%s - %s", name,
        dicom.TRANSFER_SYNTAX_NAMES[r.accepted_ts] or r.accepted_ts or "(unknown TS)")
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
  if modalities["PET"] and modalities["CT"] then
    modalities["PET-CT"] = true
  end

  local services = summarize_services(pc_results)
  out.services = stdnse.output_table()
  for _, key in ipairs(SERVICE_KEYS) do
    out.services[key] = service_line(key, services[key])
  end
  if next(classes) then out.service_classes = sorted_keys(classes) end
  if next(commands) then out.service_commands = sorted_keys(commands) end
  if next(modalities) then out.modalities = sorted_keys(modalities) end
  out.inferred_device_class = device_class(classes)

  out.results = stdnse.output_table()
  if #accepted > 0 then
    local t = stdnse.output_table()
    t.count = #accepted
    t.items = accepted
    out.results[dicom.PC_RESULT_NAMES[0]] = t
  end

  local security = stdnse.output_table()
  if info.tls then
    security.transport = "DICOM over TLS"
    if info.cert then security.certificate = cert_table(info.cert) end
  else
    security.transport = "plaintext (no TLS)"
  end
  local findings = security_findings(services,
    stdnse.get_script_args("dicom.called_aet"), info)
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

  return out
end
