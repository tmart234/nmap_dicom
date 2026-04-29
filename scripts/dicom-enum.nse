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

This script does NOT brute-force Application Entity Titles. If the target
PACS enforces an AET allowlist, the association will be rejected before any
PC results come back — use dicom-brute first to discover a valid AET pair,
then pass it via dicom.called_aet / dicom.calling_aet here.

Modeled on ssh2-enum-algos: discovery + safe categories, NOT default.
]]

---
-- @usage nmap -p 4242 --script dicom-enum <target>
-- @usage nmap -p 11112 --script dicom-enum --script-args dicom.called_aet=ORTHANC <target>
-- @usage nmap --script dicom-enum --script-args dicom-enum.ports=11114,11115 <target>
--
-- @args dicom.called_aet     Called AET. Default: ANY-SCP
-- @args dicom.calling_aet    Calling AET. Default: ECHOSCU
-- @args dicom.timeout_ms     Socket timeout in ms. Default: 3000
-- @args dicom-enum.ports     Optional comma-separated list of ports to
--                            probe (e.g. "104,11112,2761,2762,4242").
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-enum:
-- |   association: accepted (max_pdu=16384, vendor=Orthanc 1.11.0)
-- |   accepted (15):
-- |     Verification - Implicit VR Little Endian
-- |     CT Image Storage - Explicit VR Little Endian
-- |     MR Image Storage - Explicit VR Little Endian
-- |     ...
-- |   abstract-syntax-not-supported (10):
-- |     Modality Worklist FIND
-- |     Encapsulated PDF Storage
-- |     ...
-- |_  transfer-syntaxes-not-supported (3):
-- |     CR Image Storage
-- |     ...
---

author     = "Tyler M <tmart234()gmail.com>"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local dicom     = require "dicom"
local stdnse    = require "stdnse"
local table     = require "table"
local string    = require "string"

-- ---------- Curated Presentation Context list ----------
-- Abstract syntax UIDs are taken from PS3.4 (Storage / Worklist / Q-R) and
-- PS3.6 (registry of UIDs). The list is fixed for v1; per-profile presets
-- (storage-only, qr-only, ...) are an obvious follow-on PR.

local TS_I    = "1.2.840.10008.1.2"     -- Implicit VR LE
local TS_E    = "1.2.840.10008.1.2.1"   -- Explicit VR LE
local TS_EBE  = "1.2.840.10008.1.2.2"   -- Explicit VR Big Endian

local PC_LIST = {
  -- Verification
  {name = "Verification",                                uid = "1.2.840.10008.1.1",                   ts = {TS_I, TS_E}},

  -- Storage SOP classes
  {name = "CT Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.2",           ts = {TS_I, TS_E, TS_EBE}},
  {name = "Enhanced CT Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.2.1",         ts = {TS_I, TS_E}},
  {name = "MR Image Storage",                            uid = "1.2.840.10008.5.1.4.1.1.4",           ts = {TS_I, TS_E, TS_EBE}},
  {name = "Enhanced MR Image Storage",                   uid = "1.2.840.10008.5.1.4.1.1.4.1",         ts = {TS_I, TS_E}},
  {name = "Ultrasound Image Storage",                    uid = "1.2.840.10008.5.1.4.1.1.6.1",         ts = {TS_I, TS_E}},
  {name = "Ultrasound Multi-frame Image Storage",        uid = "1.2.840.10008.5.1.4.1.1.3.1",         ts = {TS_I, TS_E}},
  {name = "Computed Radiography Image Storage",          uid = "1.2.840.10008.5.1.4.1.1.1",           ts = {TS_I, TS_E}},
  {name = "Digital X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.1",      ts = {TS_I, TS_E}},
  {name = "Digital X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.1.1",    ts = {TS_I, TS_E}},
  {name = "Digital Mammography X-Ray Image Storage - For Presentation", uid = "1.2.840.10008.5.1.4.1.1.1.2",   ts = {TS_I, TS_E}},
  {name = "Digital Mammography X-Ray Image Storage - For Processing",   uid = "1.2.840.10008.5.1.4.1.1.1.2.1", ts = {TS_I, TS_E}},
  {name = "X-Ray Angiographic Image Storage",            uid = "1.2.840.10008.5.1.4.1.1.12.1",        ts = {TS_I, TS_E}},
  {name = "Secondary Capture Image Storage",             uid = "1.2.840.10008.5.1.4.1.1.7",           ts = {TS_I, TS_E}},
  {name = "Encapsulated PDF Storage",                    uid = "1.2.840.10008.5.1.4.1.1.104.1",       ts = {TS_I, TS_E}},
  {name = "Basic Text SR Storage",                       uid = "1.2.840.10008.5.1.4.1.1.88.11",       ts = {TS_I, TS_E}},
  {name = "Comprehensive SR Storage",                    uid = "1.2.840.10008.5.1.4.1.1.88.33",       ts = {TS_I, TS_E}},
  {name = "Grayscale Softcopy Presentation State Storage", uid = "1.2.840.10008.5.1.4.1.1.11.1",      ts = {TS_I, TS_E}},

  -- Worklist + Query/Retrieve
  {name = "Modality Worklist Information Model - FIND",  uid = "1.2.840.10008.5.1.4.31",              ts = {TS_I, TS_E}},
  {name = "Patient Root Query/Retrieve - FIND",          uid = "1.2.840.10008.5.1.4.1.2.1.1",         ts = {TS_I, TS_E}},
  {name = "Patient Root Query/Retrieve - MOVE",          uid = "1.2.840.10008.5.1.4.1.2.1.2",         ts = {TS_I, TS_E}},
  {name = "Patient Root Query/Retrieve - GET",           uid = "1.2.840.10008.5.1.4.1.2.1.3",         ts = {TS_I, TS_E}},
  {name = "Study Root Query/Retrieve - FIND",            uid = "1.2.840.10008.5.1.4.1.2.2.1",         ts = {TS_I, TS_E}},
  {name = "Study Root Query/Retrieve - MOVE",            uid = "1.2.840.10008.5.1.4.1.2.2.2",         ts = {TS_I, TS_E}},
  {name = "Study Root Query/Retrieve - GET",             uid = "1.2.840.10008.5.1.4.1.2.2.3",         ts = {TS_I, TS_E}},

  -- Workflow
  {name = "Storage Commitment Push Model",               uid = "1.2.840.10008.1.20.1",                ts = {TS_I, TS_E}},
  {name = "Modality Performed Procedure Step",           uid = "1.2.840.10008.3.1.2.3.3",             ts = {TS_I, TS_E}},

  -- Print
  {name = "Basic Grayscale Print Management Meta",       uid = "1.2.840.10008.5.1.1.9",               ts = {TS_I, TS_E}},
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
    local e = tostring(err or "")
    out.dicom = "DICOM Service Provider discovered!"
    if e == "ASSOCIATE REJECT received" then
      if not called_aet or called_aet == "ANY-SCP" then
        out.config = "Called AET check enabled — pass dicom.called_aet=<AET> (try dicom-brute first)"
      else
        out.config = string.format("Association rejected (tried AET: %s)", called_aet)
      end
      return out
    end
    out.error = e
    return nil
  end

  -- Build the association header line: "accepted (max_pdu=N, vendor=...)"
  local detail = {}
  if info and info.max_pdu then
    detail[#detail + 1] = string.format("max_pdu=%d", info.max_pdu)
  end
  if info and (info.impl_version or info.impl_uid) then
    local final_version, vendor, _clean, device_vendor =
      dicom.resolve_vendor_info(info.impl_version, info.impl_uid)
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
  end
  if #detail > 0 then
    out.association = string.format("accepted (%s)", table.concat(detail, ", "))
  else
    out.association = "accepted"
  end

  -- Bucket per-PC results.
  local buckets = { [0]={}, [1]={}, [2]={}, [3]={}, [4]={}, unknown={} }
  for i, r in ipairs(pc_results) do
    local pc = PC_LIST[i]
    local code = r.result
    if code == 0 then
      local line = string.format("%s - %s", pc.name, ts_label(r.accepted_ts))
      table.insert(buckets[0], line)
    elseif code == 1 or code == 2 or code == 3 or code == 4 then
      table.insert(buckets[code], pc.name)
    else
      table.insert(buckets.unknown, pc.name)
    end
  end

  for _, code in ipairs(BUCKET_ORDER) do
    local items = buckets[code]
    if items and #items > 0 then
      local key = string.format("%s (%d)", dicom.PC_RESULT_NAMES[code], #items)
      out[key] = items
    end
  end

  if #buckets.unknown > 0 then
    out[string.format("unknown-result (%d)", #buckets.unknown)] = buckets.unknown
  end

  return out
end
