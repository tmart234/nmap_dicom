--[[
Enumerates the SOP classes and transfer syntaxes a DICOM Service Provider
accepts by proposing a curated set of presentation contexts in a single
A-ASSOCIATE request and parsing the per-PC result map returned in the
A-ASSOCIATE-AC PDU (PS3.8 §9.3.3.2).

Each presentation context is reported as one of:
  accepted (0), user-rejection (1), no-reason (2),
  abstract-syntax-not-supported (3), transfer-syntaxes-not-supported (4)

This is a capability fingerprint: it identifies which Storage SOP classes
the SCP serves (CT/MR/US/CR/DX/Mammo/...), whether it supports Modality
Worklist FIND, Patient/Study Root Query/Retrieve, Storage Commitment,
MPPS, and Print Management, and which transfer syntaxes it negotiates.

The script also infers a device class (PACS/VNA, Modality, RIS gateway,
Archive front-end, Print server) from the set of accepted service classes.
This taxonomy is a practitioner consensus, not a normative DICOM concept;
treat the inferred_device_class line as a fingerprint, not a classification.

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
-- @usage nmap --script dicom-enum --script-args dicom-enum.ports=11114,11115 <target>
--
-- @args dicom.called_aet     Called AET. Default: ANY-SCP
-- @args dicom.calling_aet    Calling AET. Default: ECHOSCU
-- @args dicom.timeout_ms     Socket timeout in ms. Default: 3000
-- @args dicom.no_release     If set, the script omits A-RELEASE-RQ and lets
--                            the SCP see an aborted association. Default:
--                            unset (release is sent).
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
-- |   inferred_device_class: Archive front-end
-- |   results:
-- |     accepted:
-- |       count: 15
-- |       items:
-- |         Verification - Implicit VR Little Endian
-- |         CT Image Storage - Explicit VR Little Endian
-- |         MR Image Storage - JPEG 2000 Image Compression (Lossless Only)
-- |     abstract-syntax-not-supported:
-- |       count: 10
-- |       items:
-- |         Modality Worklist Information Model - FIND
-- |         Encapsulated PDF Storage
-- |_    transfer-syntaxes-not-supported:
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

-- ---------- Curated Presentation Context list ----------
-- Abstract syntax UIDs are taken from PS3.4 (Storage / Worklist / Q-R) and
-- PS3.6 (registry of UIDs). The list is fixed for v1; per-profile presets
-- (storage-only, qr-only, ...) are an obvious follow-on PR.

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

-- Storage SOP classes accept the full transfer-syntax matrix. PDU-size
-- sanity: 17 storage PCs × 13 TS sub-items × ~30 bytes/TS ≈ 6.6 KB plus
-- ~2 KB of non-storage PCs and headers — well under the 16 KB max PDU.
local STORAGE_TS = {
  TS_I, TS_E, TS_EBE, TS_DEFLATE,
  TS_JPEG_BL, TS_JPEG_LL, TS_JLS_LL,
  TS_J2K_LL, TS_J2K, TS_RLE,
  TS_HTJ2K_L, TS_HTJ2K_R, TS_HTJ2K,
}

-- Non-storage classes (Verification, Q/R, MWL, MPPS, StgCmt, Print) do not
-- benefit from compressed transfer syntaxes; keep the proposal minimal.
local CMD_TS = {TS_I, TS_E}

local PC_LIST = {
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

-- Order in which to render result buckets in the output table.
local BUCKET_ORDER = {0, 1, 3, 4, 2}

-- ---------- action ----------

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

action = function(host, port)
  local out = stdnse.output_table()

  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  local calling_aet = stdnse.get_script_args("dicom.calling_aet")

  -- Convert PC_LIST to the shape associate_extended expects.
  local pcs = {}
  for i, pc in ipairs(PC_LIST) do
    pcs[i] = { abstract_syntax = pc.uid, transfer_syntaxes = pc.ts }
  end

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

  -- Bucket per-PC results and collect accepted service classes.
  local buckets = { [0]={}, [1]={}, [2]={}, [3]={}, [4]={}, unknown={} }
  local accepted_services = {}
  for i, r in ipairs(pc_results) do
    local pc = PC_LIST[i]
    local code = r.result
    if code == 0 then
      table.insert(buckets[0], string.format("%s - %s", pc.name, ts_label(r.accepted_ts)))
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

  -- Device-class fingerprint (practitioner taxonomy, not normative DICOM).
  local device_class = dicom.infer_device_class(accepted_services)
  if device_class then
    out.inferred_device_class = device_class
  end

  -- Structured results: nested tables with count + items, stable XML keys.
  local results = stdnse.output_table()
  for _, code in ipairs(BUCKET_ORDER) do
    local items = buckets[code]
    if items and #items > 0 then
      local sub = stdnse.output_table()
      sub.count = #items
      sub.items = items
      results[dicom.PC_RESULT_NAMES[code]] = sub
    end
  end
  if #buckets.unknown > 0 then
    local sub = stdnse.output_table()
    sub.count = #buckets.unknown
    sub.items = buckets.unknown
    results["unknown-result"] = sub
  end
  out.results = results

  return out
end
