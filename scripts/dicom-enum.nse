description = [[
Enumerates the DICOM services exposed by a Service Class Provider (SCP).

The script proposes a curated list of commonly seen abstract syntaxes
(Verification, the major Storage SOP Classes, Modality Worklist, Patient
and Study Root Query/Retrieve, Storage Commitment Push, Modality
Performed Procedure Step, and Basic Grayscale Print Management) inside a
single A-ASSOCIATE-RQ and parses the per-Presentation-Context result
codes from the A-ASSOCIATE-AC PDU.  Each context is reported as
<code>accepted</code>, <code>user-rejection</code>, <code>no-reason</code>,
<code>abstract-syntax-not-supported</code>, or
<code>transfer-syntaxes-not-supported</code> (PS3.8 §9.3.3.2).

Unlike <code>dicom-ping</code>, which only confirms that a host speaks
DICOM and accepts the supplied AE Title pair, this script enumerates
which SOP Classes and Transfer Syntaxes the SCP advertises.  Unlike
<code>dicom-brute</code>, which sweeps Called AE Titles to find a valid
gate-passing pair, this script holds the AET pair fixed and varies the
service request.  Run <code>dicom-brute</code> first if a target enforces
strict AET allow-listing, then feed the discovered AET pair back in via
<code>--script-args dicom.called_aet=...,dicom.calling_aet=...</code>.

Reference: DICOM PS3.7 §9.3.2 (A-ASSOCIATE service), PS3.8 §9.3.3
(A-ASSOCIATE-AC PDU encoding).
]]

---
-- @usage nmap -p4242 --script dicom-enum <target>
-- @usage nmap -p4242 --script dicom-enum --script-args dicom.called_aet=ORTHANC,dicom.calling_aet=NMAP <target>
--
-- @args dicom.called_aet  Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: NMAP-DICOM
-- @args dicom.timeout_ms  Socket timeout in milliseconds. Default: 3000
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-enum:
-- |   called_aet: ANY-SCP (default)
-- |   accepted: (4)
-- |     1.2.840.10008.1.1                Verification                              [Implicit VR LE]
-- |     1.2.840.10008.5.1.4.1.1.2        CT Image Storage                          [Explicit VR LE]
-- |     1.2.840.10008.5.1.4.1.2.2.1      Study Root Q/R - FIND                     [Implicit VR LE]
-- |     1.2.840.10008.5.1.4.1.2.2.2      Study Root Q/R - MOVE                     [Implicit VR LE]
-- |   abstract-syntax-not-supported: (22)
-- |     1.2.840.10008.5.1.4.1.1.4        MR Image Storage
-- |     1.2.840.10008.5.1.4.1.1.6.1      Ultrasound Image Storage
-- |     ...
-- |_  transfer-syntaxes-not-supported: (1)
--       1.2.840.10008.5.1.4.1.1.104.1    Encapsulated PDF Storage                  [tried: Implicit VR LE, Explicit VR LE]
--
-- @xmloutput
-- <table key="accepted">
--   <table>
--     <elem key="abstract_syntax">1.2.840.10008.1.1</elem>
--     <elem key="name">Verification</elem>
--     <elem key="accepted_ts">1.2.840.10008.1.2</elem>
--     <elem key="accepted_ts_name">Implicit VR LE</elem>
--   </table>
-- </table>
---

author = "Tyler M <tmart234()gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local dicom     = require "dicom"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- Mirror dicom-ping's port set so the two scripts trigger on the same hosts
-- when no -sV match exists.
local COMMON_DICOM_PORTS = {104, 11112, 2761, 2762, 4242}

portrule = shortport.port_or_service(COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp")

-- DICOM Transfer Syntax UIDs (PS3.5 §10).
local TS_IMPLICIT_LE = "1.2.840.10008.1.2"
local TS_EXPLICIT_LE = "1.2.840.10008.1.2.1"
local TS_EXPLICIT_BE = "1.2.840.10008.1.2.2"

local TS_NAMES = {
  [TS_IMPLICIT_LE] = "Implicit VR LE",
  [TS_EXPLICIT_LE] = "Explicit VR LE",
  [TS_EXPLICIT_BE] = "Explicit VR BE",
}

local function ts_name(uid)
  if not uid then return nil end
  return TS_NAMES[uid] or uid
end

-- Curated abstract-syntax catalog. Three transfer syntaxes are offered on a
-- pair of legacy modality storage classes (CT, MR) so a strict modality that
-- only speaks Big Endian is still distinguishable from one that does not
-- support the SOP at all. Everything else uses Implicit VR LE (mandatory) and
-- Explicit VR LE (widely preferred). 27 PCs -> well under the 128-PC PS3.8
-- limit and small enough to fit in any sane SCP receive buffer.
local PC_CATALOG = {
  -- Verification
  {"1.2.840.10008.1.1",                "Verification",                              {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Storage SOP Classes
  {"1.2.840.10008.5.1.4.1.1.2",        "CT Image Storage",                          {TS_IMPLICIT_LE, TS_EXPLICIT_LE, TS_EXPLICIT_BE}},
  {"1.2.840.10008.5.1.4.1.1.2.1",      "Enhanced CT Image Storage",                 {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.4",        "MR Image Storage",                          {TS_IMPLICIT_LE, TS_EXPLICIT_LE, TS_EXPLICIT_BE}},
  {"1.2.840.10008.5.1.4.1.1.4.1",      "Enhanced MR Image Storage",                 {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.6.1",      "Ultrasound Image Storage",                  {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.3.1",      "Ultrasound Multi-frame Image Storage",      {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.1",        "Computed Radiography Image Storage",        {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.1.1",      "Digital X-Ray Image Storage - For Presentation", {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.1.1.1",    "Digital X-Ray Image Storage - For Processing",   {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.1.2",      "Digital Mammography X-Ray Image Storage - For Presentation", {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.12.1",     "X-Ray Angiographic Image Storage",          {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.7",        "Secondary Capture Image Storage",           {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.104.1",    "Encapsulated PDF Storage",                  {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.88.11",    "Basic Text SR Storage",                     {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.88.33",    "Comprehensive SR Storage",                  {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.1.11.1",     "Grayscale Softcopy Presentation State Storage", {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Modality Worklist
  {"1.2.840.10008.5.1.4.31",           "Modality Worklist Information Model - FIND", {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Patient Root Query/Retrieve
  {"1.2.840.10008.5.1.4.1.2.1.1",      "Patient Root Q/R - FIND",                   {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.2.1.2",      "Patient Root Q/R - MOVE",                   {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.2.1.3",      "Patient Root Q/R - GET",                    {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Study Root Query/Retrieve
  {"1.2.840.10008.5.1.4.1.2.2.1",      "Study Root Q/R - FIND",                     {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.2.2.2",      "Study Root Q/R - MOVE",                     {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.5.1.4.1.2.2.3",      "Study Root Q/R - GET",                      {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Storage Commitment / MPPS
  {"1.2.840.10008.1.20.1",             "Storage Commitment Push Model",             {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
  {"1.2.840.10008.3.1.2.3.3",          "Modality Performed Procedure Step",         {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},

  -- Print Management
  {"1.2.840.10008.5.1.1.9",            "Basic Grayscale Print Management Meta",     {TS_IMPLICIT_LE, TS_EXPLICIT_LE}},
}

-- Order in which result groups are rendered. Empty groups are suppressed.
local GROUP_ORDER = {
  "accepted",
  "user-rejection",
  "no-reason",
  "abstract-syntax-not-supported",
  "transfer-syntaxes-not-supported",
}

-- Map library result_name (from PC_RESULT_NAMES) to display group.
local function group_for(result_name)
  if result_name == "acceptance" then return "accepted" end
  return result_name
end

local function build_pc_list()
  local pcs = {}
  for _, entry in ipairs(PC_CATALOG) do
    table.insert(pcs, {
      abstract_syntax   = entry[1],
      transfer_syntaxes = entry[3],
    })
  end
  return pcs
end

local function format_uid_name_line(uid, name, suffix)
  -- Two-column-ish: UID padded to 36 chars, name padded to 50. Falls back
  -- gracefully if either field is unusually long.
  local left = string.format("%-36s %-48s", uid, name)
  if suffix and suffix ~= "" then
    return left .. " " .. suffix
  end
  return left
end

action = function(host, port)
  local out = stdnse.output_table()
  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  local calling_aet = stdnse.get_script_args("dicom.calling_aet")

  local pc_list = build_pc_list()

  local ok, err, results, info = dicom.associate_pcs(
    host, port, calling_aet, called_aet, pc_list,
    {impl_version = "NMAP_DICOM_ENUM"})

  if not ok then
    local e = tostring(err or "")
    if e == "ASSOCIATE REJECT received" or e == "A-ABORT received" then
      out.dicom = "DICOM Service Provider detected, association refused."
      if not called_aet or called_aet == "ANY-SCP" then
        out.config = "Called AET check enabled (run dicom-brute to find a valid AET pair)"
      else
        out.config = string.format("Association refused for AET pair (called=%s)", called_aet)
      end
      out.error = e
      return out
    end
    stdnse.debug1("dicom-enum: associate_pcs failed: %s", e)
    return nil
  end

  -- Index PC catalog by abstract syntax for human-readable name lookup.
  local name_by_uid = {}
  for _, e in ipairs(PC_CATALOG) do name_by_uid[e[1]] = e[2] end

  -- Bin results by display-group name.
  local groups = {}
  for _, name in ipairs(GROUP_ORDER) do groups[name] = {} end
  for _, r in ipairs(results) do
    local g = group_for(r.result_name)
    groups[g] = groups[g] or {}
    table.insert(groups[g], r)
  end

  out.called_aet = (called_aet and called_aet ~= "")
                   and called_aet
                    or "ANY-SCP (default)"

  -- ssh2-enum-algos pattern: each group becomes a nested array under a
  -- key with " (N)" appended; NSE renders the key on its own line and
  -- the array elements indented underneath.
  for _, gname in ipairs(GROUP_ORDER) do
    local entries = groups[gname]
    if entries and #entries > 0 then
      local rows = {}
      for _, r in ipairs(entries) do
        local human = name_by_uid[r.abstract_syntax] or "?"
        local suffix
        if gname == "accepted" then
          suffix = string.format("[%s]", ts_name(r.accepted_ts) or "?")
        elseif gname == "transfer-syntaxes-not-supported" then
          local names = {}
          for _, ts in ipairs(r.requested_ts or {}) do
            table.insert(names, ts_name(ts))
          end
          suffix = string.format("[tried: %s]", table.concat(names, ", "))
        end
        table.insert(rows, format_uid_name_line(r.abstract_syntax, human, suffix))
      end
      out[string.format("%s (%d)", gname, #entries)] = rows
    end
  end

  if info and info.impl_version_name then
    out.impl_version_name = info.impl_version_name
  end
  if info and info.impl_class_uid then
    out.impl_class_uid = info.impl_class_uid
  end

  return out
end
