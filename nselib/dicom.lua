---
-- DICOM library
--
-- This library implements (partially) the DICOM protocol. This protocol is used to
-- capture, store and distribute medical images.
--
-- From Wikipedia:
-- The core application of the DICOM standard is to capture, store and distribute
-- medical images. The standard also provides services related to imaging such as
-- managing imaging procedure worklists, printing images on film or digital media
-- like DVDs, reporting procedure status like completion of an imaging acquisition,
-- confirming successful archiving of images, encrypting datasets, removing patient
-- identifying information from datasets, organizing layouts of images for review,
-- saving image manipulations and annotations, calibrating image displays, encoding
-- ECGs, encoding CAD results, encoding structured measurement data, and storing
-- acquisition protocols.
--
-- OPTIONS:
-- *<code>called_aet</code> - If set it changes the called Application Entity Title
--                            used in the requests. Default: ANY-SCP
-- *<code>calling_aet</code> - If set it changes the calling Application Entity Title
--                            used in the requests. Default: ECHOSCU
--
-- Associations are kept gentle on production SCPs, whose association pool
-- is shared with clinical traffic: associations to a host are serialized
-- across all DICOM scripts, a transient A-ASSOCIATE-RJ (temporary-congestion
-- / local-limit-exceeded) is retried with exponential backoff, large
-- proposals are split across sequential associations, and every error path
-- after the A-ASSOCIATE-RQ sends A-ABORT so the SCP frees the slot at once.
--
-- @args dicom.called_aet Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: ECHOSCU
-- @args dicom.timeout_ms Socket timeout in milliseconds. Default: 3000
-- @args dicom.retries Retries after a transient A-ASSOCIATE-RJ
--                     (temporary-congestion / local-limit-exceeded). Default: 2
-- @args dicom.backoff_ms Delay before the first retry in milliseconds,
--                        doubled for each retry after it. Default: 2000
-- @args dicom.max_pcs Most presentation contexts proposed in one
--                     A-ASSOCIATE-RQ; larger proposals are split across
--                     sequential associations. Default: 64 (range 2-128)
-- @args dicom.max_rq_bytes Largest A-ASSOCIATE-RQ PDU sent, in bytes; larger
--                          proposals are split across sequential
--                          associations. Default: 16384
-- @args dicom.no_release If set, an accepted association is closed with
--                        A-ABORT instead of A-RELEASE-RQ. Default: unset
--
-- @author Paulino Calderon <paulino@calderonpale.com> and Tyler M <tmart234@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("dicom", stdnse.seeall)

local MIN_HEADER_LEN = 6
PDU_NAMES = {}  -- exported reverse map: pdu_type -> name (built below)

-- ITU-T X.667 self-issued OID. Generated once for Nmap's NSE DICOM stack.
-- Stable across runs (so PACS audit-log correlation works) but not under the
-- OFFIS / IANA-PEN tree, so it does not impersonate DCMTK or any registered
-- vendor. Replace with 1.3.6.1.4.1.<PEN>.1 if Insecure.Com registers a PEN.
local IMPLEMENTATION_CLASS_UID = "2.25.205477355541376756296906656564391676347"
-- Implementation Version Name (PS3.7 D.3.3.2). Stable across Nmap releases
-- so SCP fingerprinting / audit-log filtering rules don't need updating
-- whenever Nmap ships. Embed the Nmap version in port.version at the
-- script layer where it belongs, not in the wire-level identifier.
local IMPLEMENTATION_VERSION_NAME = "NMAP_NSE"

local APPLICATION_CONTEXT_NAME = "1.2.840.10008.3.1.1.1"
local MAX_PDU_LEN = 16384
-- A-ASSOCIATE-RQ fixed fields between the PDU header and the first variable
-- item: protocol version, reserved, called/calling AE titles, reserved
-- (PS3.8 §9.3.2).
local RQ_FIXED_LEN = 68

-- Presentation context IDs are odd integers 1-255 (PS3.8 §9.3.2.2), so one
-- A-ASSOCIATE-RQ can carry at most 128. Some real SCPs (older DCMTK builds,
-- GE, embedded modality stacks) refuse far smaller RQ PDUs, so proposals are
-- split well below that ceiling by default.
local MAX_PCS_PER_RQ       = 128
local DEFAULT_MAX_PCS      = 64
local DEFAULT_MAX_RQ_BYTES = 16384

local DEFAULT_RETRIES    = 2
local DEFAULT_BACKOFF_MS = 2000
-- Pause before each follow-up association of a split proposal. SCPs can free
-- a pool slot a moment after sending A-RELEASE-RP (pynetdicom with a
-- one-slot pool rejected 4 of 10 immediate re-associations), so starting the
-- next one at once can draw a local-limit-exceeded reject.
local BATCH_GAP_MS = 250

-- A-ABORT source and reason/diag values (PS3.8 §9.3.8). The reason is only
-- significant when the source is the UL service-provider.
local ABORT_SOURCE_USER           = 0
local ABORT_SOURCE_PROVIDER       = 2
local ABORT_REASON_NOT_SPECIFIED  = 0
local ABORT_REASON_UNEXPECTED_PDU = 2

-- A-ASSOCIATE-AC PDU layout (PS3.8 §9.3.3 Table 9-17).
-- 6-byte PDU header + 68-byte fixed preamble = 74; first variable item starts
-- at 1-indexed Lua offset 75.
local AC_VARIABLE_ITEM_OFFSET = 75
-- Item / sub-item types (PS3.8 §9.3.3.2 Table 9-18, §9.3.3.2.1 Table 9-19,
-- §9.3.3.3, PS3.7 D.3.3).
local ITEM_PC_AC               = 0x21
local ITEM_TRANSFER_SYNTAX     = 0x40
local ITEM_USER_INFORMATION    = 0x50
local SUBITEM_MAX_PDU          = 0x51
local SUBITEM_IMPL_CLASS_UID   = 0x52
local SUBITEM_IMPL_VERSION     = 0x55

-- ===== Local Helper Functions =====

local function ul_item(item_type, value_bytes)
  return string.pack(">B B I2", item_type, 0x00, #value_bytes) .. value_bytes
end

local function item_application_context(uid) return ul_item(0x10, uid) end
local function item_abstract_syntax(uid)    return ul_item(0x30, uid) end
local function item_transfer_syntax(uid)    return ul_item(0x40, uid) end

local function item_presentation_context(pc_id, abstract_uid, transfer_uids)
  local header = string.pack(">B B B B", pc_id, 0x00, 0x00, 0x00)
  local ts_blob = ""
  -- Accept either a single UID string or a list of UIDs.
  if type(transfer_uids) == "string" then
    ts_blob = item_transfer_syntax(transfer_uids)
  else
    for _, uid in ipairs(transfer_uids) do
      ts_blob = ts_blob .. item_transfer_syntax(uid)
    end
  end
  local payload = header .. item_abstract_syntax(abstract_uid) .. ts_blob
  return ul_item(0x20, payload)
end

local function item_max_pdu(max_len)
  return string.pack(">B B I2 I4", 0x51, 0x00, 0x0004, max_len)
end
local function item_impl_uid(uid)     return ul_item(0x52, uid) end
local function item_impl_version(ver) return ul_item(0x55, ver) end

local function item_user_information(impl_uid, impl_ver, max_pdu_len)
  local payload = item_max_pdu(max_pdu_len) .. item_impl_uid(impl_uid) .. item_impl_version(impl_ver)
  return ul_item(0x50, payload)
end

local function pad16(s)
  s = (s or ""):sub(1,16)
  if #s < 16 then s = s .. string.rep(" ", 16 - #s) end
  return s
end

-- ==================================

local PDU_CODES = {
  ASSOCIATE_REQUEST  = 0x01,
  ASSOCIATE_ACCEPT   = 0x02,
  ASSOCIATE_REJECT   = 0x03,
  DATA               = 0x04,
  RELEASE_REQUEST    = 0x05,
  RELEASE_RESPONSE   = 0x06,
  ABORT              = 0x07
}

for i, v in pairs(PDU_CODES) do
  PDU_NAMES[v] = i
end

-- Per-PC result codes returned in A-ASSOCIATE-AC (PS3.8 §9.3.3.2)
PC_RESULT_NAMES = {
  [0] = "accepted",
  [1] = "user-rejection",
  [2] = "no-reason",
  [3] = "abstract-syntax-not-supported",
  [4] = "transfer-syntaxes-not-supported",
}

-- A-ASSOCIATE-RJ field decoding (PS3.8 §9.3.4 Table 9-21)
ASSOC_RJ_RESULT = {
  [1] = "rejected-permanent",
  [2] = "rejected-transient",
}
ASSOC_RJ_SOURCE = {
  [1] = "DICOM-UL-service-user",
  [2] = "DICOM-UL-service-provider-ACSE",
  [3] = "DICOM-UL-service-provider-Presentation",
}
ASSOC_RJ_REASON = {
  [1] = {
    [1] = "no-reason-given",
    [2] = "application-context-not-supported",
    [3] = "calling-AE-title-not-recognized",
    [7] = "called-AE-title-not-recognized",
  },
  [2] = {
    [1] = "no-reason-given",
    [2] = "protocol-version-not-supported",
  },
  [3] = {
    [0] = "reserved",
    [1] = "temporary-congestion",
    [2] = "local-limit-exceeded",
  },
}

-- Common DICOM Transfer Syntax UIDs
TRANSFER_SYNTAX_UIDS = {
  IMPLICIT_VR_LE       = "1.2.840.10008.1.2",
  EXPLICIT_VR_LE       = "1.2.840.10008.1.2.1",
  EXPLICIT_VR_BE       = "1.2.840.10008.1.2.2",
  DEFLATE_EXPLICIT_LE  = "1.2.840.10008.1.2.1.99",
  JPEG_BASELINE        = "1.2.840.10008.1.2.4.50",
  JPEG_LOSSLESS        = "1.2.840.10008.1.2.4.70",
  JPEG_LS_LOSSLESS     = "1.2.840.10008.1.2.4.80",
  JPEG_2000_LOSSLESS   = "1.2.840.10008.1.2.4.90",
  JPEG_2000_LOSSY      = "1.2.840.10008.1.2.4.91",
  RLE_LOSSLESS         = "1.2.840.10008.1.2.5",
  HTJ2K_LOSSLESS       = "1.2.840.10008.1.2.4.201",
  HTJ2K_LOSSLESS_RPCL  = "1.2.840.10008.1.2.4.202",
  HTJ2K                = "1.2.840.10008.1.2.4.203",
}

-- Friendly names for the TS UIDs we may propose
TRANSFER_SYNTAX_NAMES = {
  ["1.2.840.10008.1.2"]       = "Implicit VR Little Endian",
  ["1.2.840.10008.1.2.1"]     = "Explicit VR Little Endian",
  ["1.2.840.10008.1.2.2"]     = "Explicit VR Big Endian",
  ["1.2.840.10008.1.2.1.99"]  = "Deflated Explicit VR Little Endian",
  ["1.2.840.10008.1.2.4.50"]  = "JPEG Baseline (Process 1)",
  ["1.2.840.10008.1.2.4.70"]  = "JPEG Lossless, Non-Hierarchical, First-Order Prediction",
  ["1.2.840.10008.1.2.4.80"]  = "JPEG-LS Lossless",
  ["1.2.840.10008.1.2.4.90"]  = "JPEG 2000 Image Compression (Lossless Only)",
  ["1.2.840.10008.1.2.4.91"]  = "JPEG 2000 Image Compression",
  ["1.2.840.10008.1.2.5"]     = "RLE Lossless",
  ["1.2.840.10008.1.2.4.201"] = "HTJ2K Lossless",
  ["1.2.840.10008.1.2.4.202"] = "HTJ2K Lossless RPCL",
  ["1.2.840.10008.1.2.4.203"] = "HTJ2K",
}

-- DICOM SOP-Class UID -> functional service-class mapping.
-- Sources: PS3.4 Annex A (Verification), Annex B (Storage), Annex C (Q/R),
-- Annex F (MPPS), Annex H (Print), Annex J (Storage Commitment),
-- Annex K (Modality Worklist), Annex CC (UPS), Annex DD (GP Worklist).
-- Order matters: most-specific entry must appear before any prefix that
-- would also match.
SERVICE_CLASS_BY_UID = {
  {uid = "1.2.840.10008.1.1",                   service = "Verification"},
  {uid = "1.2.840.10008.1.20.1",                service = "Storage-Commitment"},
  {uid = "1.2.840.10008.3.1.2.3.3",             service = "MPPS"},
  {uid = "1.2.840.10008.5.1.4.31",              service = "Modality-Worklist"},
  {uid = "1.2.840.10008.5.1.4.32.",             service = "GP-Worklist", prefix = true},
  {uid = "1.2.840.10008.5.1.4.34.",             service = "UPS",         prefix = true},
  {uid = "1.2.840.10008.5.1.4.1.2.1.",          service = "QR-Patient-Root",  prefix = true},
  {uid = "1.2.840.10008.5.1.4.1.2.2.",          service = "QR-Study-Root",    prefix = true},
  {uid = "1.2.840.10008.5.1.4.1.2.3.",          service = "QR-Patient-Study", prefix = true},
  {uid = "1.2.840.10008.5.1.4.1.1.",            service = "Storage", prefix = true},
  {uid = "1.2.840.10008.5.1.1.",                service = "Print",   prefix = true},
}

---
-- Map an Abstract Syntax UID to its DICOM functional service class.
-- @return service-class string, or nil if no match.
function service_class_for_uid(uid)
  if not uid then return nil end
  for _, entry in ipairs(SERVICE_CLASS_BY_UID) do
    if entry.prefix then
      if uid:sub(1, #entry.uid) == entry.uid then return entry.service end
    elseif uid == entry.uid then
      return entry.service
    end
  end
  return nil
end

---
-- Best-effort device-class fingerprint from the set of accepted service
-- classes. The taxonomy (PACS/VNA/Modality/RIS-gateway/Archive/Print) is a
-- practitioner consensus, not a normative DICOM concept; cf. Mildenberger
-- 2002 (PMID 11960356) and the structural division between PACS and VNA in
-- the radiology informatics literature.
-- @param accepted_services set-shaped table where keys are service strings.
-- @return device-class string, or nil if the pattern is ambiguous.
function infer_device_class(accepted_services)
  if not accepted_services then return nil end
  local function has(s) return accepted_services[s] and true or false end
  local has_qr = has("QR-Patient-Root") or has("QR-Study-Root") or has("QR-Patient-Study")
  if has("Storage") and has_qr and (has("Modality-Worklist") or has("MPPS") or has("Storage-Commitment")) then
    return "PACS/VNA"
  end
  if has("Storage") and has_qr then
    return "Archive front-end"
  end
  if has("Modality-Worklist") and not has("Storage") then
    return "RIS gateway / worklist broker"
  end
  if has("Print") then
    return "Print server"
  end
  if has("Verification") and not has("Storage") and not has_qr then
    return "Modality (or unconfigured SCP)"
  end
  return nil
end

-- DICOM Storage SOP-Class UID -> imaging modality. Sourced from PS3.4 Annex B
-- and the PS3.6 UID registry. Order matters: most-specific UIDs (with the
-- longer suffixes) come before any prefix that would also match.
SOP_MODALITY_BY_UID = {
  -- CT
  {uid = "1.2.840.10008.5.1.4.1.1.2.1",         modality = "CT"},
  {uid = "1.2.840.10008.5.1.4.1.1.2.2",         modality = "CT"},
  {uid = "1.2.840.10008.5.1.4.1.1.2",           modality = "CT"},
  -- MR
  {uid = "1.2.840.10008.5.1.4.1.1.4.1",         modality = "MRI"},
  {uid = "1.2.840.10008.5.1.4.1.1.4.2",         modality = "MRI"},
  {uid = "1.2.840.10008.5.1.4.1.1.4.3",         modality = "MRI"},
  {uid = "1.2.840.10008.5.1.4.1.1.4.4",         modality = "MRI"},
  {uid = "1.2.840.10008.5.1.4.1.1.4",           modality = "MRI"},
  -- Ultrasound
  {uid = "1.2.840.10008.5.1.4.1.1.3.1",         modality = "Ultrasound"},
  {uid = "1.2.840.10008.5.1.4.1.1.6.1",         modality = "Ultrasound"},
  {uid = "1.2.840.10008.5.1.4.1.1.6.2",         modality = "Ultrasound"},
  -- Mammography (must come before generic DX/CR Storage prefixes)
  {uid = "1.2.840.10008.5.1.4.1.1.1.2.1",       modality = "Mammography"},
  {uid = "1.2.840.10008.5.1.4.1.1.1.2",         modality = "Mammography"},
  {uid = "1.2.840.10008.5.1.4.1.1.13.1.3",      modality = "Mammography"},
  -- Intra-oral / dentistry (more specific than generic X-Ray)
  {uid = "1.2.840.10008.5.1.4.1.1.1.3.1",       modality = "X-Ray (Intra-oral)"},
  {uid = "1.2.840.10008.5.1.4.1.1.1.3",         modality = "X-Ray (Intra-oral)"},
  -- Digital X-Ray (DR)
  {uid = "1.2.840.10008.5.1.4.1.1.1.1.1",       modality = "X-Ray (DX)"},
  {uid = "1.2.840.10008.5.1.4.1.1.1.1",         modality = "X-Ray (DX)"},
  -- Computed Radiography
  {uid = "1.2.840.10008.5.1.4.1.1.1",           modality = "X-Ray (CR)"},
  -- X-Ray Angiography
  {uid = "1.2.840.10008.5.1.4.1.1.12.1.1",      modality = "X-Ray Angiography"},
  {uid = "1.2.840.10008.5.1.4.1.1.12.1",        modality = "X-Ray Angiography"},
  -- X-Ray Radiofluoroscopy
  {uid = "1.2.840.10008.5.1.4.1.1.12.2.1",      modality = "Fluoroscopy"},
  {uid = "1.2.840.10008.5.1.4.1.1.12.2",        modality = "Fluoroscopy"},
  -- Nuclear Medicine
  {uid = "1.2.840.10008.5.1.4.1.1.20",          modality = "Nuclear Medicine"},
  -- PET (PET-CT scanners emit both PET and CT Storage SOP classes)
  {uid = "1.2.840.10008.5.1.4.1.1.130",         modality = "PET"},
  {uid = "1.2.840.10008.5.1.4.1.1.128.1",       modality = "PET"},
  {uid = "1.2.840.10008.5.1.4.1.1.128",         modality = "PET"},
  -- Endoscopy / Visible Light
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.1.1",    modality = "Endoscopy"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.1",      modality = "Endoscopy"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.4.1",    modality = "VL Photographic"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.4",      modality = "VL Photographic"},
  -- Radiotherapy
  {uid = "1.2.840.10008.5.1.4.1.1.481.1",       modality = "RT Image"},
  -- Ophthalmology
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.5.1",    modality = "Ophthalmic Photography"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.5.2",    modality = "Ophthalmic Photography"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.5.4",    modality = "Ophthalmic Tomography (OCT)"},
  -- Cardiology / physiological waveforms
  {uid = "1.2.840.10008.5.1.4.1.1.9.1.1",       modality = "ECG (Waveform)"},
  {uid = "1.2.840.10008.5.1.4.1.1.9.1.2",       modality = "ECG (Waveform)"},
  {uid = "1.2.840.10008.5.1.4.1.1.9.1.3",       modality = "ECG (Waveform)"},
  -- Digital pathology / microscopy
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.2",      modality = "Microscopy"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.2.1",    modality = "Microscopy"},
  {uid = "1.2.840.10008.5.1.4.1.1.77.1.6",      modality = "Whole Slide Imaging"},
  -- Document / non-image objects (no implied physical modality)
  {uid = "1.2.840.10008.5.1.4.1.1.7",           modality = "Secondary Capture"},
  {uid = "1.2.840.10008.5.1.4.1.1.104.1",       modality = "Encapsulated Document"},
}

---
-- Map a Storage SOP-Class UID to its imaging modality. Returns nil for
-- non-Storage UIDs (Verification, Q/R, MWL, Print, ...).
function modality_for_uid(uid)
  if not uid then return nil end
  for _, entry in ipairs(SOP_MODALITY_BY_UID) do
    if uid == entry.uid then return entry.modality end
  end
  return nil
end

---
-- Build the sorted set of modalities implied by a list of accepted abstract
-- syntax UIDs. PET-CT is collapsed when both PET and CT are present.
function infer_modalities(accepted_uids)
  if not accepted_uids then return {} end
  local set = {}
  for _, uid in ipairs(accepted_uids) do
    local m = modality_for_uid(uid)
    if m then set[m] = true end
  end
  if set["PET"] and set["CT"] then
    set["PET-CT"] = true
  end
  local list = {}
  for m in pairs(set) do list[#list + 1] = m end
  table.sort(list)
  return list
end

-- PS3.4 Service Classes reported by infer_services(), in output order. Query/
-- Retrieve (Annex C) is split into its query (C-FIND) and retrieve (C-MOVE,
-- C-GET) halves; Modality Worklist is the Basic Worklist Management Service
-- (Annex K), a separate Service Class whose C-FIND runs against a different
-- information model.
SERVICE_KEYS = {
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
local QR_MODEL_NAMES = {
  ["1.2.840.10008.5.1.4.1.2.1"] = "Patient Root",
  ["1.2.840.10008.5.1.4.1.2.2"] = "Study Root",
  ["1.2.840.10008.5.1.4.1.2.3"] = "Patient/Study Only",
}

-- Map a SOP Class UID to its SERVICE_KEYS entry, DIMSE ops, and an optional
-- label naming the Q/R information model or UPS / Print SOP Class.
local function dimse_for_uid(uid)
  local d = DIMSE_BY_UID[uid]
  if d then return d.service, d.ops, d.label end
  if uid:sub(1, #STORAGE_UID_PREFIX) == STORAGE_UID_PREFIX then
    return "storage", {"C-STORE"}, nil
  end
  if uid:sub(1, #QR_UID_PREFIX) == QR_UID_PREFIX then
    local model, tail = uid:match("^(.*)%.([123])$")
    local op = tail and QR_OPS[tail]
    if op then
      return (op == "C-FIND") and "query" or "retrieve", {op}, QR_MODEL_NAMES[model] or model
    end
  end
  return nil
end

local function sorted_keys(set)
  local list = {}
  for k in pairs(set) do list[#list + 1] = k end
  table.sort(list)
  return list
end

---
-- Infer DIMSE service commands from accepted abstract syntax UIDs: C-ECHO,
-- C-STORE, C-FIND, C-MOVE and C-GET for the composite services, and the
-- N-* operations (N-CREATE, N-SET, N-ACTION, N-EVENT-REPORT, N-GET,
-- N-DELETE) for MPPS, Storage Commitment, UPS and Print Management.
-- @return sorted list of DIMSE operation names.
function infer_service_commands(accepted_uids)
  local cmds = {}
  for _, uid in ipairs(accepted_uids or {}) do
    local _, ops = dimse_for_uid(uid)
    for _, op in ipairs(ops or {}) do cmds[op] = true end
  end
  return sorted_keys(cmds)
end

---
-- Summarize negotiation per PS3.4 Service Class (see SERVICE_KEYS).
-- @param proposed_uids abstract syntaxes the SCP answered, accepted or not
-- @param accepted_uids abstract syntaxes it accepted
-- @return table keyed by SERVICE_KEYS entry. A key is absent when no context
--         for that service was proposed; otherwise it maps to
--         {accepted = bool, sop_classes = n, ops = {[op] = sorted labels}},
--         where labels name the Q/R information models or UPS / Print SOP
--         Classes that carry the op (empty for single-SOP-Class services).
function infer_services(proposed_uids, accepted_uids)
  local out = {}
  local function entry(svc)
    out[svc] = out[svc] or { accepted = false, sop_classes = 0, ops = {} }
    return out[svc]
  end
  for _, uid in ipairs(proposed_uids or {}) do
    local svc = dimse_for_uid(uid)
    if svc then entry(svc) end
  end
  local seen = {}
  for _, uid in ipairs(accepted_uids or {}) do
    local svc, ops, label = dimse_for_uid(uid)
    if svc and not seen[uid] then
      seen[uid] = true
      local s = entry(svc)
      s.accepted = true
      s.sop_classes = s.sop_classes + 1
      for _, op in ipairs(ops) do
        s.ops[op] = s.ops[op] or {}
        if label then s.ops[op][label] = true end
      end
    end
  end
  for _, s in pairs(out) do
    for op, labels in pairs(s.ops) do s.ops[op] = sorted_keys(labels) end
  end
  return out
end

-- UID tables: "toolkit" = DICOM library on the wire (CVE target),
-- "manufacturer" = device OEM (asset inventory).
-- Most-specific patterns first within each table.

local TOOLKIT_UID_PATTERNS = {
  {"^1%.3%.6%.1%.4%.1%.25403%.",              "ClearCanvas"},
  {"^1%.3%.6%.1%.4%.1%.30071%.8",             "fo-dicom"},
  {"^1%.2%.826%.0%.1%.3680043%.9%.3811%.",    "pynetdicom"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.641%.",     "Orthanc"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.",    "OsiriX/Horos"},
  {"^1%.2%.276%.0%.7230010%.3%.",             "DCMTK"},
  {"^1%.2%.40%.0%.13%.1%.3",                  "dcm4che"},
  {"^1%.2%.826%.0%.1%.3680043%.2%.135%.1066%.101", "ConQuest"},
}

local MANUFACTURER_UID_PATTERNS = {
  {"^1%.2%.840%.113619%.",                    "GE Healthcare"},
  {"^1%.3%.12%.2%.1107%.",                    "Siemens"},
  {"^1%.2%.840%.114257%.",                    "Agfa"},
  {"^1%.2%.840%.113704%.",                    "Philips"},
  {"^1%.3%.46%.670589%.",                     "Philips"},
  {"^1%.2%.840%.113564%.",                    "Carestream"},
  {"^1%.2%.392%.200036%.",                    "Fujifilm"},
  {"^1%.2%.840%.113669%..*",                  "Merge Healthcare"},
}

-- Known toolkit signatures in Implementation Version Name (0x55).
-- Case-insensitive plain-text match against the cleaned value.
-- More-specific substrings must come before any prefix that would also match.
local TOOLKIT_PATTERNS = {
  {"offis",          "DCMTK"},
  {"dcmtk",          "DCMTK"},
  {"mergecom",       "Merge Healthcare SDK"},
  {"dcm4che",        "dcm4che"},
  {"pynetdicom",     "pynetdicom"},
  {"leadtools",      "LeadTools"},
  {"clearcanvas",    "ClearCanvas"},
  {"orthanc",        "Orthanc"},
  {"osirix",         "OsiriX"},
  {"horos",          "Horos"},
  {"conquest",       "ConQuest"},
  {"dgate",          "ConQuest"},
  {"fo-dicom",       "fo-dicom"},
  {"dicomobjects",   "DICOMObjects"},  -- DicomObjects.NET default
  {"dcmobj",         "DICOMObjects"},  -- DicomObjects.COM default ("DCMOBJw.x.y.z")
  {"logipacs",       "LogiPACS"},
  {"neologica",      "LogiPACS"},
}

--- Check whether two canonical vendor/toolkit names refer to the same entity.
-- Handles cases like toolkit="OsiriX" vs org="OsiriX/Horos" where a substring
-- match is sufficient to declare equivalence.
local function names_match(a, b)
  if not a or not b then return false end
  if a == b then return true end
  if a:find(b, 1, true) or b:find(a, 1, true) then return true end
  return false
end

---
-- start_connection(host, port) starts socket to DICOM service
---
function start_connection(host, port)
  local dcm = {}
  dcm['socket'] = nmap.new_socket()

  -- Transport selection (PS3.15 §B.1 DICOM-over-TLS):
  --   dicom.tls=true  -> force a TLS association
  --   dicom.tls=false -> force plaintext
  --   unset           -> adapt to Nmap's own SSL/TLS service detection
  -- (so `-sV` on an stunnel-fronted SCP, or the dicom-tls service name, is
  -- honoured without a script-arg).
  local protocol = "tcp"
  local is_ssl = false

  local tls_arg = stdnse.get_script_args("dicom.tls")
  if tls_arg == "true" then
    is_ssl = true
  elseif tls_arg == "false" then
    is_ssl = false
  else
    if port.version and port.version.service_tunnel == "ssl" then
      is_ssl = true
    end
    if port.version and type(port.version.name) == "string" and port.version.name:match("tls") then
      is_ssl = true
    end
  end

  if is_ssl then
    protocol = "ssl"
    stdnse.debug1("DICOM: Upgrading to SSL/TLS")
  end

  local ok, err = dcm['socket']:connect(host, port, protocol)
  if ok == false then
    return false, "DICOM: Failed to connect to host: " .. err
  end

  local t = tonumber(stdnse.get_script_args("dicom.timeout_ms")) or 3000
  dcm['socket']:set_timeout(t)

  -- Record the negotiated transport so association helpers can report it and
  -- fetch the peer certificate.
  dcm['is_ssl'] = is_ssl
  return true, dcm
end

---
-- send(dcm, data) Sends DICOM packet over established socket
---
function send(dcm, data)
  if not dcm['socket'] then return false, "No socket found." end
  stdnse.debug2("DICOM: Sending DICOM packet (%d bytes)", #data)
  return dcm['socket']:send(data)
end

---
-- receive(dcm) Reads DICOM PDUs over an established socket.
---
function receive(dcm)
  local sock = dcm['socket']
  if not sock then return false, "No socket" end

  local function is_timeout(err)
    local e = tostring(err or ""):lower()
    return e:find("timed out", 1, true) or e:find("timeout", 1, true) or e:find("time out", 1, true)
  end

  local ok1, chunk = sock:receive_bytes(6)
  if not ok1 then
    if is_timeout(chunk) then return false, "TIMEOUT" end
    return false, chunk
  end
  if #chunk < 6 then return false, "Short PDU header" end

  local header = chunk:sub(1, 6)
  local _pdu_type, _, pdu_length = string.unpack(">B B I4", header)
  local body = chunk:sub(7)
  local need = pdu_length - #body

  while need > 0 do
    local ok2, more = sock:receive_bytes(need)
    if not ok2 then
      if is_timeout(more) then return false, "TIMEOUT" end
      return false, more
    end
    -- Prevent buffer over-read if the server sends the next PDU immediately
    body = body .. string.sub(more, 1, need)
    need = pdu_length - #body
  end

  return true, header .. body
end

---
-- pdu_header_encode(pdu_type, length) encodes the DICOM PDU header
---
function pdu_header_encode(pdu_type, length)
  if type(pdu_type) ~= "number" or type(length) ~= "number" then
    return false, "PDU Type and Length must be numbers."
  end
  local header = string.pack(">B B I4", pdu_type, 0, length)
  return true, header
end

-- Close the transport once; repeat calls are no-ops so error paths can tear
-- down unconditionally.
local function close(dcm)
  if dcm['socket'] and not dcm['closed'] then
    dcm['closed'] = true
    dcm['socket']:close()
  end
end

---
-- abort(dcm, source, reason) sends an A-ABORT PDU (PS3.8 §9.3.8) and closes
-- the transport. Used on every error path once the A-ASSOCIATE-RQ is out, so
-- the SCP frees the association slot immediately instead of holding it until
-- its own ARTIM or idle timer fires. Best-effort: send errors are ignored.
-- @param source 0 = DICOM UL service-user (default), 2 = UL service-provider
-- @param reason Reason/diag, significant only when source is 2. Default: 0
---
function abort(dcm, source, reason)
  if not dcm or not dcm['socket'] or dcm['closed'] then return end
  source = source or ABORT_SOURCE_USER
  reason = reason or ABORT_REASON_NOT_SPECIFIED
  local _, header = pdu_header_encode(PDU_CODES["ABORT"], 4)
  stdnse.debug1("DICOM: Sending A-ABORT (source=%d, reason=%d)", source, reason)
  send(dcm, header .. string.pack(">B B B B", 0, 0, source, reason))
  close(dcm)
end

-- ==================== Parse Sub-Routines ====================

---
-- parse_associate_accept(data) walks an A-ASSOCIATE-AC PDU and returns:
--   {
--     pc_results   = { [pc_id] = {result = N, accepted_ts = uid_or_nil} },
--     max_pdu      = number_or_nil,
--     impl_uid     = string_or_nil,        -- 0x52
--     impl_version = string_or_nil,        -- 0x55
--   }
-- Item structure follows PS3.8 §9.3.3.
function parse_associate_accept(data)
  local out = { pc_results = {}, max_pdu = nil, impl_uid = nil, impl_version = nil }
  local data_len = #data
  if data_len < AC_VARIABLE_ITEM_OFFSET - 1 then return out end

  local offset = AC_VARIABLE_ITEM_OFFSET

  while offset + 3 <= data_len do
    local item_type = string.byte(data, offset)
    local item_len  = string.unpack(">I2", data, offset + 2)
    local val_start = offset + 4
    local val_end   = offset + 3 + item_len
    if val_end > data_len then break end

    if item_type == ITEM_PC_AC and item_len >= 4 then
      -- Presentation Context AC item
      local pc_id     = string.byte(data, val_start)
      local pc_result = string.byte(data, val_start + 2)
      local entry     = { result = pc_result, accepted_ts = nil }

      -- PS3.8 §9.3.3.2 Table 9-18: when result ≠ 0, the Transfer Syntax
      -- sub-item value "shall not be tested when received". Skip it.
      if pc_result == 0 then
        local sub = val_start + 4
        while sub + 3 <= val_end do
          local stype = string.byte(data, sub)
          local slen  = string.unpack(">I2", data, sub + 2)
          local svs   = sub + 4
          local sve   = sub + 3 + slen
          if sve > val_end then break end
          if stype == ITEM_TRANSFER_SYNTAX and slen > 0 then
            local raw = data:sub(svs, sve)
            entry.accepted_ts = (raw:gsub("%z", "")):match("^%s*(.-)%s*$")
          end
          sub = sub + 4 + slen
        end
      end

      out.pc_results[pc_id] = entry

    elseif item_type == ITEM_USER_INFORMATION then
      -- User Information item
      local sub = val_start
      while sub + 3 <= val_end do
        local stype = string.byte(data, sub)
        local slen  = string.unpack(">I2", data, sub + 2)
        local svs   = sub + 4
        local sve   = sub + 3 + slen
        if sve > val_end then break end

        if stype == SUBITEM_MAX_PDU and slen >= 4 then
          out.max_pdu = string.unpack(">I4", data, svs)
        elseif stype == SUBITEM_IMPL_CLASS_UID and slen > 0 then
          local raw = data:sub(svs, sve)
          out.impl_uid = (raw:gsub("%z", "")):match("^%s*(.-)%s*$")
        elseif stype == SUBITEM_IMPL_VERSION and slen > 0 then
          local raw = data:sub(svs, sve)
          out.impl_version = (raw:gsub("%z", "")):match("^%s*(.-)%s*$")
        end

        sub = sub + 4 + slen
      end
    end

    offset = offset + 4 + item_len
  end

  return out
end

function parse_implementation_version(data)
  local version, uid = nil, nil
  local data_len = #data

  if data_len < AC_VARIABLE_ITEM_OFFSET - 1 then
    return nil, nil
  end

  local offset = AC_VARIABLE_ITEM_OFFSET
  local userinfo_start = nil

  -- Walk the TLV structure to find User Information item (0x50)
  while offset + 3 <= data_len do
    local item_type = string.byte(data, offset)
    local item_len  = string.unpack(">I2", data, offset + 2)

    if item_type == ITEM_USER_INFORMATION then
      userinfo_start = offset
      break
    end
    offset = offset + 4 + item_len
  end

  if not userinfo_start then
      stdnse.debug2("User Information item (0x50) not found during TLV walk.")
      return nil, nil
  end

  if userinfo_start + 3 > data_len then return nil, nil end

  local userinfo_len = string.unpack(">I2", data, userinfo_start + 2)
  local sub_offset = userinfo_start + 4
  local effective_end = math.min(userinfo_start + 3 + userinfo_len, data_len)

  -- Walk sub-items inside User Info
  while sub_offset + 3 <= effective_end do
    local sub_type = string.byte(data, sub_offset)
    local sub_len  = string.unpack(">I2", data, sub_offset + 2)
    local sub_value_start = sub_offset + 4
    local sub_value_end   = sub_offset + 3 + sub_len

    if sub_value_end <= effective_end and sub_len > 0 then
      local value_raw = data:sub(sub_value_start, sub_value_end)
      local value_cleaned = value_raw:gsub("%z", ""):match("^%s*(.-)%s*$")

      if sub_type == SUBITEM_IMPL_CLASS_UID and not uid then
          uid = value_cleaned
      elseif sub_type == SUBITEM_IMPL_VERSION and not version then
          version = value_cleaned
      end
    end

    sub_offset = sub_offset + 4 + sub_len
  end

  return version, uid
end

---
-- Identify the Implementation Class UID (0x52) against both UID tables.
-- Returns: name, category ("toolkit" or "manufacturer", or nil if no match)
--
function identify_vendor_from_uid(uid)
  if not uid then return nil, nil end
  uid = uid:gsub("%z", ""):match("^%s*(.-)%s*$")

  for _, entry in ipairs(TOOLKIT_UID_PATTERNS) do
    if uid:match(entry[1]) then
      stdnse.debug1("DICOM: 0x52 UID -> toolkit: %s", entry[2])
      return entry[2], "toolkit"
    end
  end

  for _, entry in ipairs(MANUFACTURER_UID_PATTERNS) do
    if uid:match(entry[1]) then
      stdnse.debug1("DICOM: 0x52 UID -> manufacturer: %s", entry[2])
      return entry[2], "manufacturer"
    end
  end

  stdnse.debug1("DICOM: 0x52 UID unrecognized: %s", uid)
  return nil, nil
end

---
-- Identify the toolkit from the Implementation Version Name (0x55).
-- Returns a canonical toolkit name, or nil if unrecognized.
--
function identify_toolkit(version_str)
  if not version_str then return nil end
  local s = version_str:gsub("%z", ""):match("^%s*(.-)%s*$")
  if s == "" then return nil end
  local low = s:lower()
  for _, entry in ipairs(TOOLKIT_PATTERNS) do
    if low:find(entry[1], 1, true) then
      stdnse.debug1("DICOM: 0x55 -> toolkit: %s (from: %s)", entry[2], s)
      return entry[2]
    end
  end
  stdnse.debug1("DICOM: 0x55 unrecognized: %s", s)
  return nil
end

function extract_clean_version(version_str, vendor)
  if not version_str then return nil end
  local s = version_str:gsub("%z", ""):match("^%s*(.-)%s*$")
  if s == "" then return nil end
  local v = vendor and vendor:lower() or nil

  if v == "dcmtk" or s:find("DCMTK", 1, true) or s:find("OFFIS", 1, true) then
    local a,b,c = s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk].-[ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    a,b,c = s:match("[Dd][Cc][Mm][Tt][Kk][ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    local sem = s:match("[Dd][Cc][Mm][Tt][Kk][%s_/-]*([%d]+%.%d+%.%d+)")
             or s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk][%s_/-]*([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "pynetdicom" or s:find("PYNETDICOM") or s:lower():find("pynetdicom") then
    -- Modern pynetdicom (>= 2.x) emits PYNETDICOM_<MAJ>.<MIN>.<PATCH> with
    -- dot separators, e.g. PYNETDICOM_3.0.4. Older forms used underscore-
    -- joined three-digit shorthand (PYNETDICOM_300) which is unambiguous
    -- only for single-digit components and is no longer attempted.
    local sem = s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s_/:-]+([%d]+%.%d+%.%d+)")
             or s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s_/:-]+([%d]+%.%d+)")
    if sem then return sem end
  end

  if v == "dcm4che" or s:lower():find("dcm4che") then
    local sem = s:match("dcm4che[%w-]*[%s/:-]+([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "orthanc" or s:lower():find("orthanc") then
    local sem = s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+%.%d+)")
             or s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+)")
    if sem then return sem end
  end

  if v == "osirix" or v == "horos" or s:lower():find("osirix") or s:lower():find("horos") then
    local sem = s:match("[vV]([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  if v == "clearcanvas" or s:find("ClearCanvas") then
    local maj, min, build = s:match("ClearCanvas[_-](%d+)%.(%d+)%.(%d+)")
    if maj and min and build then return string.format("%s.%s.%s", maj, min, build) end

    maj, min = s:match("ClearCanvas[_-](%d+)%.(%d+)")
    if maj and min then return string.format("%s.%s", maj, min) end
  end

  -- fo-dicom emits "fo-dicom <Major>.<Minor>.<Build>" per
  -- FO-DICOM.Core/DicomImplementation.cs (GetImplementationVersion()).
  if v == "fo-dicom" or s:lower():find("fo-dicom", 1, true) then
    local sem = s:match("[Ff][Oo]%-[Dd][Ii][Cc][Oo][Mm][%s_/:-]+([%d]+%.%d+%.%d+)")
             or s:match("[Ff][Oo]%-[Dd][Ii][Cc][Oo][Mm][%s_/:-]+([%d]+%.%d+)")
    if sem then return sem end
  end

  -- DicomObjects.COM default Implementation Version Name is "DCMOBJw.x.y.z"
  -- per Medical Connections KB. The .NET variant emits "DicomObjects.NET"
  -- with no embedded version, so version stays nil there.
  if v == "dicomobjects" or s:lower():find("dcmobj", 1, true) then
    local sem = s:match("[Dd][Cc][Mm][Oo][Bb][Jj][%s_/:-]*(%d+%.%d+%.%d+%.%d+)")
             or s:match("[Dd][Cc][Mm][Oo][Bb][Jj][%s_/:-]*(%d+%.%d+%.%d+)")
             or s:match("[Dd][Cc][Mm][Oo][Bb][Jj][%s_/:-]*(%d+%.%d+)")
    if sem then return sem end
  end

  -- Generic fallbacks
  local sem = s:match("(%d+%.%d+%.%d+)")
  if sem then return sem end
  sem = s:match("(%d+%.%d+)")
  if sem then return sem end

  return s
end

-- ============================================================

---
-- resolve_vendor_info(received_version_str, received_uid_str)
-- Maps the raw 0x55 / 0x52 strings to (final_version, parsed_vendor,
-- parsed_clean_version, device_vendor, impl_version_name) using the
-- toolkit-first resolution policy. Shared by associate() and dicom-enum.
function resolve_vendor_info(received_version_str, received_uid_str)
  local impl_version_name = received_version_str

  local toolkit_name = identify_toolkit(received_version_str)
  local uid_name, uid_category = identify_vendor_from_uid(received_uid_str)

  local parsed_vendor, parsed_clean_version, device_vendor = nil, nil, nil

  if toolkit_name then
    parsed_vendor = toolkit_name
    parsed_clean_version = extract_clean_version(received_version_str, toolkit_name)
    stdnse.debug1("DICOM: Vendor from 0x55: %s", toolkit_name)

    if uid_name then
      if uid_category == "manufacturer" then
        device_vendor = uid_name
        stdnse.debug1("DICOM: Device manufacturer from 0x52: %s", uid_name)
      elseif uid_category == "toolkit" and not names_match(uid_name, toolkit_name) then
        stdnse.debug1("DICOM: 0x52 toolkit (%s) differs from 0x55 (%s) — using 0x55", uid_name, toolkit_name)
      end
    end

  elseif uid_name and uid_category == "toolkit" then
    parsed_vendor = uid_name
    stdnse.debug1("DICOM: Vendor from 0x52 toolkit: %s", uid_name)
    if received_version_str then
      parsed_clean_version = extract_clean_version(received_version_str, uid_name)
    end

  elseif uid_name and uid_category == "manufacturer" then
    device_vendor = uid_name
    stdnse.debug1("DICOM: 0x52 manufacturer (%s), no toolkit from 0x55", uid_name)
    if received_version_str then
      parsed_clean_version = extract_clean_version(received_version_str, nil)
    end

  elseif received_version_str then
    local v = received_version_str:lower()
    if     v:find("dcm4che",   1, true) then parsed_vendor = "dcm4che"
    elseif v:find("dcmtk",     1, true) then parsed_vendor = "DCMTK"
    elseif v:find("pynetdicom",1, true) then parsed_vendor = "pynetdicom"
    elseif v:find("orthanc",   1, true) then parsed_vendor = "Orthanc"
    end
    if parsed_vendor then
      stdnse.debug1("DICOM: Vendor from 0x55 fallback: %s", parsed_vendor)
    else
      stdnse.debug1("DICOM: No vendor. 0x55=%s, 0x52=%s",
        tostring(received_version_str), tostring(received_uid_str))
    end
    parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
  else
    stdnse.debug1("DICOM: No identification data (0x55 and 0x52 both empty)")
  end

  local final_version = parsed_clean_version or impl_version_name
  return final_version, parsed_vendor, parsed_clean_version, device_vendor, impl_version_name
end

-- ==================== Association ====================

-- Close an accepted association with A-RELEASE-RQ and wait for A-RELEASE-RP
-- (PS3.8 §9.1, §9.3.6). Skipping the release makes SCPs log an abort, which
-- fires abort-rate alerts in clinical environments. If the RP never arrives
-- (timeout, stray PDU), fall back to A-ABORT rather than leaving the
-- association half-released on the SCP.
local function release(dcm)
  local _, header = pdu_header_encode(PDU_CODES["RELEASE_REQUEST"], 4)
  local ok, resp = send(dcm, header .. "\0\0\0\0")
  if ok then
    ok, resp = receive(dcm)
  end
  local resp_type = ok and string.byte(resp, 1) or nil
  if resp_type == PDU_CODES["RELEASE_RESPONSE"] or resp_type == PDU_CODES["ABORT"] then
    close(dcm)
  else
    stdnse.debug1("DICOM: No A-RELEASE-RP (%s); aborting",
      ok and ("got PDU type " .. tostring(resp_type)) or tostring(resp))
    abort(dcm)
  end
end

-- Run one association over a connected transport: send the A-ASSOCIATE-RQ,
-- read the reply, then release. Every exit either ends cleanly (release
-- completed, or the SCP already ended it with A-ASSOCIATE-RJ / A-ABORT) or
-- sends A-ABORT. On accept returns true, nil, results, info where
-- results[k] is the outcome of presentation_contexts[k].
local function negotiate(dcm, calling_aet, called_aet, presentation_contexts)
  local pc_blocks = {}
  for k, pc in ipairs(presentation_contexts) do
    -- odd IDs per PS3.8 §9.3.2.2
    pc_blocks[k] = item_presentation_context(2 * k - 1, pc.abstract_syntax, pc.transfer_syntaxes)
  end

  local fixed = string.pack(">I2 I2 c16 c16 c32",
    0x0001, 0x0000, pad16(called_aet or "ANY-SCP"), pad16(calling_aet or "ECHOSCU"), string.rep("\0", 32))
  local assoc_body = fixed .. item_application_context(APPLICATION_CONTEXT_NAME)
    .. table.concat(pc_blocks)
    .. item_user_information(IMPLEMENTATION_CLASS_UID, IMPLEMENTATION_VERSION_NAME, MAX_PDU_LEN)
  local _, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_body)

  local send_status, send_err = send(dcm, header .. assoc_body)
  if not send_status then
    abort(dcm)
    return false, string.format("Couldn't send ASSOCIATE request: %s", send_err or "Unknown error")
  end

  local receive_status, response_data = receive(dcm)
  if not receive_status then
    -- Timeout or short read: the SCP may still hold a half-open association.
    abort(dcm)
    return false, string.format("Couldn't read ASSOCIATE response: %s", response_data)
  end

  local resp_type = string.byte(response_data, 1)
  if resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
    -- The SCP closes the transport after A-ASSOCIATE-RJ; nothing to abort.
    close(dcm)
    -- PS3.8 §9.3.4 Table 9-21: A-ASSOCIATE-RJ body bytes after the 6-byte
    -- PDU header are: reserved, result, source, reason/diag.
    local result, source, reason
    if #response_data >= 10 then
      result = string.byte(response_data, 8)
      source = string.byte(response_data, 9)
      reason = string.byte(response_data, 10)
    end
    return false, {
      err         = "ASSOCIATE REJECT received",
      result      = result,
      source      = source,
      reason      = reason,
      result_text = result and ASSOC_RJ_RESULT[result] or nil,
      source_text = source and ASSOC_RJ_SOURCE[source] or nil,
      reason_text = (source and ASSOC_RJ_REASON[source] and reason)
                    and ASSOC_RJ_REASON[source][reason] or nil,
    }
  elseif resp_type == PDU_CODES["ABORT"] then
    close(dcm)
    return false, string.format("Received A-ABORT (source=%s, reason=%s)",
      tostring(string.byte(response_data, 9)), tostring(string.byte(response_data, 10)))
  elseif resp_type ~= PDU_CODES["ASSOCIATE_ACCEPT"] then
    abort(dcm, ABORT_SOURCE_PROVIDER, ABORT_REASON_UNEXPECTED_PDU)
    return false, "Received unexpected response PDU type: " .. tostring(resp_type)
  end

  local parsed = parse_associate_accept(response_data)

  -- On a TLS association, grab the peer certificate before we close the
  -- socket so the caller can report issuer/validity/key-strength. Best-effort:
  -- a stack without get_ssl_certificate just yields a nil cert.
  local peer_cert
  if dcm['is_ssl'] then
    local okc, cert = pcall(function() return dcm['socket']:get_ssl_certificate() end)
    if okc then peer_cert = cert end
  end

  if stdnse.get_script_args("dicom.no_release") ~= nil then
    abort(dcm)
  else
    release(dcm)
  end

  local results = {}
  for k in ipairs(presentation_contexts) do
    local pc_id = 2 * k - 1
    local raw   = parsed.pc_results[pc_id] or {}
    results[k] = { pc_id = pc_id, result = raw.result, accepted_ts = raw.accepted_ts }
  end

  return true, nil, results, {
    max_pdu      = parsed.max_pdu,
    impl_uid     = parsed.impl_uid,
    impl_version = parsed.impl_version,
    tls          = dcm['is_ssl'] or false,
    cert         = peer_cert,
  }
end

-- One association attempt. A Lua error mid-negotiation (say, a parser bug
-- tripped by a malformed A-ASSOCIATE-AC) still sends A-ABORT before it
-- propagates.
local function associate_once(host, port, calling_aet, called_aet, pcs)
  local status, dcm = start_connection(host, port)
  if not status then
    return false, dcm
  end
  local r = table.pack(pcall(negotiate, dcm, calling_aet, called_aet, pcs))
  if not r[1] then
    abort(dcm)
    error(r[2], 0)
  end
  return table.unpack(r, 2, r.n)
end

-- A-ASSOCIATE-RJ from the UL service-provider (presentation related) with
-- temporary-congestion or local-limit-exceeded: the SCP's association pool
-- is full, so a later attempt may succeed (PS3.8 §9.3.4).
local function is_busy_reject(err)
  return type(err) == "table" and err.source == 3 and (err.reason == 1 or err.reason == 2)
end

local function associate_with_retry(host, port, calling_aet, called_aet, pcs)
  local retries = math.max(0, math.floor(tonumber(stdnse.get_script_args("dicom.retries")) or DEFAULT_RETRIES))
  local backoff = tonumber(stdnse.get_script_args("dicom.backoff_ms")) or DEFAULT_BACKOFF_MS
  local r
  for attempt = 0, retries do
    if attempt > 0 then
      local delay = math.floor(backoff * 2 ^ (attempt - 1))
      stdnse.debug1("DICOM: SCP busy (%s); retry %d/%d in %d ms",
        r[2].reason_text or "?", attempt, retries, delay)
      stdnse.sleep(delay / 1000)
    end
    r = table.pack(associate_once(host, port, calling_aet, called_aet, pcs))
    if r[1] or not is_busy_reject(r[2]) then break end
  end
  return table.unpack(r, 1, r.n)
end

-- Serialize associations to one host across every DICOM script in the run.
-- SCPs cap concurrent associations (often 10-50, shared with modalities and
-- workstations), and parallel NSE threads -- several DICOM ports on one PACS,
-- or dicom-ping and dicom-enum together -- could otherwise fill the pool and
-- lock out clinical traffic. The lock is held through retry backoff so the
-- wait is genuinely quiet on the wire.
local function associate_serialized(host, port, calling_aet, called_aet, pcs)
  local key = type(host) == "table" and host.ip or tostring(host)
  local mutex = nmap.mutex("dicom-association-" .. key)
  mutex "lock"
  local r = table.pack(pcall(associate_with_retry, host, port, calling_aet, called_aet, pcs))
  mutex "done"
  if not r[1] then error(r[2], 0) end
  return table.unpack(r, 2, r.n)
end

-- Encoded length of one presentation-context item. The PC ID is a fixed
-- one-byte field, so a placeholder ID gives the exact size.
local function pc_item_len(pc)
  return #item_presentation_context(1, pc.abstract_syntax, pc.transfer_syntaxes)
end

-- A-ASSOCIATE-RQ size before any presentation-context items.
local RQ_BASE_LEN = MIN_HEADER_LEN + RQ_FIXED_LEN
  + #item_application_context(APPLICATION_CONTEXT_NAME)
  + #item_user_information(IMPLEMENTATION_CLASS_UID, IMPLEMENTATION_VERSION_NAME, MAX_PDU_LEN)

-- Follow-up associations also propose Verification, which virtually every
-- SCP accepts. SCPs that reject or abort a request with no acceptable
-- context (pynetdicom aborts) would otherwise turn "nothing in this batch is
-- supported" into a failed association.
local ANCHOR_PC = {
  abstract_syntax   = "1.2.840.10008.1.1",
  transfer_syntaxes = { TRANSFER_SYNTAX_UIDS.IMPLICIT_VR_LE },
}

-- Split proposal indices into per-association batches under max_pcs and
-- max_bytes. Batches after the first start with the anchor (index 0). A
-- context too large to share an RQ still goes out, in a batch of its own.
local function plan_batches(pcs, max_pcs, max_bytes)
  local anchor_len = pc_item_len(ANCHOR_PC)
  local batches = {}
  local cur, real, size = {}, 0, RQ_BASE_LEN
  for i, pc in ipairs(pcs) do
    local len = pc_item_len(pc)
    if real > 0 and (#cur >= max_pcs or size + len > max_bytes) then
      batches[#batches + 1] = cur
      cur, real, size = { 0 }, 0, RQ_BASE_LEN + anchor_len
    end
    cur[#cur + 1] = i
    real = real + 1
    size = size + len
  end
  batches[#batches + 1] = cur
  return batches
end

local function err_text(err)
  if type(err) == "table" then
    return string.format("%s (%s / %s / %s)", err.err,
      err.result_text or "?", err.source_text or "?", err.reason_text or "?")
  end
  return tostring(err)
end

---
-- associate_extended(host, port, calling_aet, called_aet, presentation_contexts)
-- Generalized A-ASSOCIATE that accepts a list of presentation contexts:
--   { {abstract_syntax = uid, transfer_syntaxes = {uid, ...}}, ... }
-- A proposal over dicom.max_pcs contexts or dicom.max_rq_bytes bytes is split
-- across sequential associations. If a follow-up association fails, the
-- remaining ones are skipped rather than pressing a struggling SCP further.
-- On accept, returns:
--   true, nil, pc_results, info
-- where:
--   pc_results[i] = {pc_id, result, accepted_ts, abstract_syntax, transfer_syntaxes}
--   info          = {max_pdu, impl_uid, impl_version, tls, cert,
--                    associations, associations_planned, errors}
-- pc_results is keyed by the index of the input list (1..N), preserving order.
-- info.associations counts the accepted associations out of the
-- info.associations_planned the proposal was split into; info.errors (nil
-- when complete) describes a failed follow-up association, whose contexts and
-- any after it have a nil result.
-- If the first association fails, returns false, err (a string, or a table
-- decoding the A-ASSOCIATE-RJ).
function associate_extended(host, port, calling_aet, called_aet, presentation_contexts)
  if not presentation_contexts or #presentation_contexts == 0 then
    return false, "presentation_contexts must contain at least one entry"
  end

  local max_pcs = math.floor(tonumber(stdnse.get_script_args("dicom.max_pcs")) or DEFAULT_MAX_PCS)
  max_pcs = math.max(2, math.min(MAX_PCS_PER_RQ, max_pcs))
  local max_bytes = tonumber(stdnse.get_script_args("dicom.max_rq_bytes")) or DEFAULT_MAX_RQ_BYTES

  local batches = plan_batches(presentation_contexts, max_pcs, max_bytes)
  if #batches > 1 then
    stdnse.debug1("DICOM: Splitting %d presentation contexts across %d associations",
      #presentation_contexts, #batches)
  end

  local pc_results, info, errors, accepted = {}, nil, {}, 0
  for b, batch in ipairs(batches) do
    local pcs = {}
    for k, i in ipairs(batch) do
      pcs[k] = (i == 0) and ANCHOR_PC or presentation_contexts[i]
    end
    if b > 1 then
      stdnse.sleep(BATCH_GAP_MS / 1000)
    end
    local ok, err, results, batch_info = associate_serialized(host, port, calling_aet, called_aet, pcs)
    if not ok then
      if b == 1 then return false, err end
      errors[#errors + 1] = string.format("association %d of %d failed: %s", b, #batches, err_text(err))
      break
    end
    accepted = accepted + 1
    info = info or batch_info
    for k, i in ipairs(batch) do
      if i > 0 then pc_results[i] = results[k] end
    end
  end

  -- Attach the proposal to each result so the caller doesn't need to
  -- cross-reference.
  for i, pc in ipairs(presentation_contexts) do
    local r = pc_results[i] or {}
    r.abstract_syntax   = pc.abstract_syntax
    r.transfer_syntaxes = pc.transfer_syntaxes
    pc_results[i] = r
  end

  info.associations = accepted
  info.associations_planned = #batches
  info.errors = (#errors > 0) and errors or nil
  return true, nil, pc_results, info
end

---
-- associate(host, port) Attempts to associate to a DICOM Service Provider
-- using a single Verification PC with Implicit + Explicit VR LE transfer
-- syntaxes (still ping-shaped — one PC, ~22 bytes more on the wire).
-- Returns on success:
--   true, nil, version, vendor, uid, impl_version_name, device_vendor
-- On failure:
--   false, err_string[, reject] where reject is the decoded A-ASSOCIATE-RJ
--   table (see associate_extended) when the SCP rejected the association.
--
function associate(host, port, calling_aet, called_aet)
  local pcs = {{
    abstract_syntax   = "1.2.840.10008.1.1",
    transfer_syntaxes = {
      "1.2.840.10008.1.2",   -- Implicit VR Little Endian
      "1.2.840.10008.1.2.1", -- Explicit VR Little Endian
    },
  }}

  local ok, err, _pc_results, info = associate_extended(host, port, calling_aet, called_aet, pcs)
  if not ok then
    -- Preserve the legacy string contract for callers (dicom-brute.nse) that
    -- pre-date the structured RJ table return.
    if type(err) == "table" then return false, err.err, err end
    return false, err
  end

  local impl_version = info and info.impl_version or nil
  local impl_uid     = info and info.impl_uid or nil
  local final_version, parsed_vendor, _clean, device_vendor, impl_version_name =
    resolve_vendor_info(impl_version, impl_uid)

  return true, nil, final_version, parsed_vendor, impl_uid, impl_version_name, device_vendor
end

function send_pdata(dicom, data)
  local status, header = pdu_header_encode(PDU_CODES["DATA"], #data)
  if status == false then
    return false, header
  end
  local err
  status, err = send(dicom, header .. data)
  if status == false then
    return false, err
  end
  return true
end

function extract_uid_root(uid)
  if not uid then return nil end
  local trimmed = uid:gsub("%z",""):match("^%s*(.-)%s*$")
  if trimmed == "" then return nil end
  return trimmed:match("^([%d%.]+)%.[^%.]+$") or trimmed
end

return _ENV