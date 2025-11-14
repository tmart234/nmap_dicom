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
-- @args dicom.called_aet Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: ECHOSCU
-- 
-- @author Paulino Calderon <paulino@calderonpale.com> and Tyler M <tmart234@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("dicom", stdnse.seeall)

local MIN_SIZE_ASSOC_REQ = 68
local MAX_SIZE_PDU = 128000
local MIN_HEADER_LEN = 6
local PDU_NAMES = {}

-- generic "UL item" helper: ItemType, 0x00, I2 length, value
local function ul_item(item_type, value_bytes)
  return string.pack(">B B I2", item_type, 0x00, #value_bytes) .. value_bytes
end

-- application-context (0x10), abstract-syntax (0x30), transfer-syntax (0x40)
local function item_application_context(uid) return ul_item(0x10, uid) end
local function item_abstract_syntax(uid)    return ul_item(0x30, uid) end
local function item_transfer_syntax(uid)    return ul_item(0x40, uid) end

-- presentation-context (0x20) with one abstract + one transfer syntax
local function item_presentation_context(pc_id, abstract_uid, transfer_uid)
  -- PC ID (1), rsvd (1), rsvd (1), result/ reason (1=0 in RQ)
  local header = string.pack(">B B B B", pc_id, 0x00, 0x00, 0x00)
  local payload = header .. item_abstract_syntax(abstract_uid) .. item_transfer_syntax(transfer_uid)
  return ul_item(0x20, payload)
end

-- user-information (0x50): max PDU (0x51), impl class UID (0x52), impl version (0x55)
local function item_max_pdu(max_len)
  return string.pack(">B B I2 I4", 0x51, 0x00, 0x0004, max_len)
end
local function item_impl_uid(uid)     return ul_item(0x52, uid) end
local function item_impl_version(ver) return ul_item(0x55, ver) end

local function item_user_information(impl_uid, impl_ver, max_pdu_len)
  local payload = item_max_pdu(max_pdu_len) .. item_impl_uid(impl_uid) .. item_impl_version(impl_ver)
  return ul_item(0x50, payload)
end

-- pad AE titles to exactly 16 bytes
local function pad16(s)
  s = (s or ""):sub(1,16)
  if #s < 16 then s = s .. string.rep(" ", 16 - #s) end
  return s
end

local PDU_CODES = {}

PDU_CODES =
{
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

-- Most-specific FIRST. Only org roots known to be used as Implementation Class UIDs.
local VENDOR_UID_PATTERNS = {
  -- Projects under UK NHS OID tree
  {"^1%.3%.6%.1%.4%.1%.25403%.",              "ClearCanvas"},
  {"^1%.2%.826%.0%.1%.3680043%.9%.3811%.",    "pynetdicom"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.641%.",     "Orthanc"},
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.",    "OsiriX/Horos"},

  -- DCMTK / OFFIS
  {"^1%.2%.276%.0%.7230010%.3%.",                "DCMTK"},

  -- dcm4che / dcm4chee
  {"^1%.2%.40%.0%.13%.1%.3$",                "dcm4che"},

  -- Major vendors (org roots)
  {"^1%.2%.840%.113619%.",                    "GE Healthcare"},
  {"^1%.3%.12%.2%.1107%.",                    "Siemens"},
  {"^1%.2%.840%.114257%.",                    "Agfa"},
  {"^1%.2%.840%.113704%.",                    "Philips"},
  {"^1%.2%.840%.113564%.",                    "Carestream"},
  {"^1%.2%.392%.200036%.",                    "Fujifilm"},
  {"^1%.2%.840%.113669%..*",                  "Merge Healthcare"},
  {"^1%.3%.46%.670589%.",                     "Philips"},
  
  -- Community PACS
  {"^1%.2%.826%.0%.1%.3680043%.2%.135%.1066%.101$", "ConQuest"},
}

---
-- start_connection(host, port) starts socket to DICOM service
--
-- @param host Host object
-- @param port Port table
-- @return (status, socket) If status is true, socket of DICOM object is set.
--                          If status is false, socket is the error message.
---
function start_connection(host, port)
  local dcm = {}
  dcm['socket'] = nmap.new_socket()

  local ok, err = dcm['socket']:connect(host, port, "tcp")
  if ok == false then
    return false, "DICOM: Failed to connect to host: " .. err
  end

  local t = tonumber(stdnse.get_script_args("dicom.timeout_ms")) or 3000
  dcm['socket']:set_timeout(t)  -- milliseconds

  return true, dcm
end

---
-- send(dcm, data) Sends DICOM packet over established socket
--
-- @param dcm DICOM object
-- @param data Data to send
-- @return status True if data was sent correctly, otherwise false and error message is returned.
---
function send(dcm, data) 
  local status, err
  stdnse.debug2("DICOM: Sending DICOM packet (%d)", #data)
  if dcm['socket'] then
    status, err = dcm['socket']:send(data)
    if status == false then
      return false, err
    end
  else 
    return false, "No socket found. Check your DICOM object"
  end
  return true
end


---
-- receive(dcm) Reads DICOM PDUs over an established socket.
-- Normalizes any socket timeout into the literal string "TIMEOUT"
-- so callers (e.g., the NSE script) can classify it as a discovery.
--
-- @param dcm DICOM object
-- @return (status, data_or_err) True + full PDU bytes, or False + error ("TIMEOUT" on timeout)
---
function receive(dcm)
  local sock = dcm['socket']
  if not sock then return false, "No socket" end

  local function is_timeout(err)
    local e = tostring(err or ""):lower()
    -- nsock errors vary a bit; catch the common phrasings
    return e:find("timed out", 1, true)
        or e:find("timeout",   1, true)
        or e:find("time out",  1, true)
  end

  -- Read at least 6 bytes (PDU header)
  local ok1, chunk = sock:receive_bytes(6)
  if ok1 == false then
    if is_timeout(chunk) then return false, "TIMEOUT" end
    return false, chunk
  end
  if #chunk < 6 then return false, "Short PDU header" end

  local header = chunk:sub(1, 6)
  local pdu_type, _, pdu_length = string.unpack(">B B I4", header)

  -- Anything beyond the first 6 is already part of the body
  local body = chunk:sub(7)
  local need = pdu_length - #body

  while need > 0 do
    local ok2, more = sock:receive_bytes(need)
    if ok2 == false then
      if is_timeout(more) then return false, "TIMEOUT" end
      return false, more
    end
    body = body .. more
    need = pdu_length - #body
  end

  stdnse.debug1("DICOM: receive() read %d bytes", 6 + #body)
  return true, header .. body
end

---
-- pdu_header_encode(pdu_type, length) encodes the DICOM PDU header
--
-- @param pdu_type PDU type as ann unsigned integer
-- @param length Length of the DICOM message
-- @return (status, dcm) If status is true, the DICOM object with the header set is returned.
--                       If status is false, dcm is the error message.
---
function pdu_header_encode(pdu_type, length)
  -- Some simple sanity checks, we do not check ranges to allow users to create malformed packets.
  if type(pdu_type) ~= "number" then
    return false, "PDU Type must be an unsigned integer. Range:0-7"
  end
  if type(length) ~= "number" then
    return false, "Length must be an unsigned integer."
  end


  local header = string.pack(">B B I4",
                            pdu_type, -- PDU Type ( 1 byte - unsigned integer in Big Endian )
                            0,        -- Reserved section ( 1 byte that should be set to 0x0 )
                            length)   -- PDU Length (4 bytes - unsigned integer in Big Endian, network order)
  if #header < MIN_HEADER_LEN then
    return false, "Header must be at least 6 bytes. Something went wrong."
  end
   return true, header
end

---
-- parse_implementation_version(data) Extracts implementation version and UID from DICOM A-ASSOCIATE-AC PDU
--
-- @param data Full A-ASSOCIATE-AC PDU data
-- @return version, uid Implementation version string and UID (both can be nil)
---
function parse_implementation_version(data)
  stdnse.debug1("Parsing implementation info from response of length %d", #data)
  local version, uid = nil, nil
  local data_len = #data

  -- Minimum length check for PDU header + fixed fields up to User Info Item marker
  if data_len < 72 then -- Approx offset where User Info might start
    stdnse.debug1("Response too short for reliable User Information parsing: %d bytes", data_len)
    return nil, nil
  end

  -- *** Find User Information item (Type 0x50, Reserved 0x00) ***
  local userinfo_marker = string.char(0x50, 0x00)
  local userinfo_start = data:find(string.char(0x50, 0x00), 7, true)

  if not userinfo_start then
      stdnse.debug1("User Information item (0x50 0x00) marker not found.")
      return nil, nil
  end
  stdnse.debug2("Found User Information marker at offset %d", userinfo_start)

  -- Check if there's enough data for User Info Length field
  if userinfo_start + 3 > data_len then
     stdnse.debug1("Not enough data for User Information length field at offset %d.", userinfo_start)
     return nil, nil
  end

  -- Get User Info Item Length and calculate boundaries
  local _, userinfo_len = string.unpack(">I2", data, userinfo_start + 2)
  local userinfo_payload_start = userinfo_start + 4
  local userinfo_payload_end = userinfo_start + 3 + userinfo_len
  stdnse.debug2("User Information Item Type 0x50 found. Length: %d. Payload byte range: %d - %d", userinfo_len, userinfo_payload_start, userinfo_payload_end)

  -- Truncate effective boundary if declared length exceeds actual PDU data
  local effective_userinfo_end = userinfo_payload_end
  if userinfo_payload_end > data_len then
     stdnse.debug1("User Information item's declared end (%d) exceeds PDU data length (%d). Truncating parse boundary to PDU length.", userinfo_payload_end, data_len)
     effective_userinfo_end = data_len
  end
  if userinfo_payload_start > effective_userinfo_end then
      stdnse.debug1("User Information payload start offset (%d) is beyond its end offset (%d). Cannot parse sub-items.", userinfo_payload_start, effective_userinfo_end)
      return nil, nil
  end

  -- *** Iterate through sub-items within User Information payload ***
  local offset = userinfo_payload_start
  local MAX_REASONABLE_SUBITEM_LEN = 256
  local MAX_SUBITEMS = 20 -- << Increased limit
  local item_count = 0

  while offset <= effective_userinfo_end - 4 and item_count < MAX_SUBITEMS do
    item_count = item_count + 1

    -- Read Type and Reserved bytes
    local sub_type = string.byte(data, offset)
    local reserved_byte = string.byte(data, offset + 1)
    stdnse.debug2("Parsing sub-item #%d at offset %d. Type: 0x%02X, Reserved: 0x%02X", item_count, offset, sub_type, reserved_byte)

    local advance_offset = 4 -- Default advance

    if reserved_byte ~= 0x00 then
      stdnse.debug1("Sub-item type 0x%02X at offset %d has non-zero reserved byte (0x%02X). Skipping header.", sub_type, offset, reserved_byte)
    elseif sub_type ~= 0x51 and sub_type ~= 0x52 and sub_type ~= 0x55 and sub_type ~= 0x53 and sub_type ~= 0x54 then
      stdnse.debug1("Unexpected or unhandled sub-item type 0x%02X encountered at offset %d. Skipping header.", sub_type, offset)
    else
      -- Type is known and reserved byte is OK.
      -- *** Add focused debugging for length ***
      local length_bytes_str = data:sub(offset + 2, offset + 3)
      local lb1 = string.byte(length_bytes_str, 1)
      local lb2 = string.byte(length_bytes_str, 2)
      stdnse.debug1("[DEBUG] Attempting to unpack length bytes at offset %d: 0x%02X 0x%02X", offset + 2, lb1, lb2)

      local success, length_val = pcall(string.unpack, ">I2", data, offset + 2)
      local sub_length = -1 -- Default to invalid length

      if success and length_val ~= nil then
         sub_length = length_val
         stdnse.debug1("[DEBUG] Successfully unpacked sub_length: %d", sub_length)
      else
         stdnse.debug1("[DEBUG] pcall/unpack FAILED for length. Status: %s, Value: %s", tostring(success), tostring(length_val))
      end
      -- *** End focused debugging ***

      local sub_value_start = offset + 4
      local sub_value_end = offset + 3 + sub_length
      stdnse.debug1("[DEBUG] Calculated sub_value_end: %d (using sub_length %d)", sub_value_end, sub_length)

      -- Check for reasons to skip processing the *value*
      if sub_length < 0 then -- Check if unpack failed
          stdnse.debug1("Failed to get valid length (%d). Skipping header.", sub_length)
          -- advance_offset remains 4
      elseif sub_length > MAX_REASONABLE_SUBITEM_LEN then
          stdnse.debug1("Sub-item reported length %d seems excessive (>%d). Skipping value.", sub_length, MAX_REASONABLE_SUBITEM_LEN)
          -- advance_offset remains 4
      elseif sub_value_end > effective_userinfo_end then
          stdnse.debug1("[DEBUG] Boundary check: sub_value_end (%d) > effective_userinfo_end (%d) -> TRUE", sub_value_end, effective_userinfo_end)
          stdnse.debug1("Boundary check failed: Sub-item calculated end offset %d exceeds User Info payload boundary (%d). Skipping value.", sub_value_end, effective_userinfo_end)
          -- advance_offset remains 4
      else
          -- Item looks completely valid and fits within boundaries. Process it.
          stdnse.debug1("[DEBUG] Boundary check: sub_value_end (%d) > effective_userinfo_end (%d) -> FALSE. Processing.", sub_value_end, effective_userinfo_end)
          stdnse.debug2("Sub-item looks valid. Processing value.")
          if sub_length > 0 then
             -- ... (value extraction logic remains the same) ...
              local value_raw = data:sub(sub_value_start, sub_value_end)
              local value_cleaned = value_raw:gsub("%z", ""):gsub("^%s*", ""):gsub("%s*$", "")

              if sub_type == 0x52 then -- Implementation Class UID
                  if not uid then
                      uid = value_cleaned
                      stdnse.debug1("Extracted Implementation Class UID (0x52): '%s'", uid)
                  else
                      stdnse.debug2("Ignoring subsequent Implementation Class UID: '%s'", value_cleaned)
                  end
              elseif sub_type == 0x55 then -- Implementation Version Name
                  if not version then
                      version = value_cleaned
                      stdnse.debug1("Extracted Implementation Version Name (0x55): '%s'", version)
                  else
                      stdnse.debug2("Ignoring subsequent Implementation Version Name: '%s'", value_cleaned)
                  end
              elseif sub_type == 0x51 then -- Maximum Length Received
                   if sub_length == 4 then
                      local max_len = string.unpack(">I4", value_raw)
                      stdnse.debug1("Extracted Max PDU Length Received (0x51): %d", max_len)
                   else
                       stdnse.debug1("Incorrect length (%d) for Max PDU Length sub-item (0x51). Expected 4.", sub_length)
                   end
              end
          else
               stdnse.debug2("Sub-item (type 0x%02X) has zero length.", sub_type)
          end
          -- Set offset advancement based on this valid item's size
          advance_offset = 4 + sub_length
      end
    end

    -- Advance the offset for the next iteration based on outcome
    offset = offset + advance_offset

  end -- while loop

  if item_count >= MAX_SUBITEMS then
    stdnse.debug1("Reached maximum sub-item limit (%d) while parsing User Information.", MAX_SUBITEMS)
  end

  stdnse.debug1("Finished parsing User Info sub-items. Final extracted values - Version: '%s', UID: '%s'", version or "nil", uid or "nil")
  return version, uid
end

function identify_vendor_from_uid(uid)
  if not uid then return nil end
  uid = uid:gsub("%z", ""):match("^%s*(.-)%s*$")  -- trim
  for _, entry in ipairs(VENDOR_UID_PATTERNS) do
    local pat, vendor = entry[1], entry[2]
    if uid:match(pat) then
      stdnse.debug2("UID '%s' matched '%s' -> '%s'", uid, pat, vendor)
      return vendor
    end
  end
  stdnse.debug2("UID '%s' did not match any known vendor patterns.", uid)
  return nil
end


---
-- extract_clean_version(version_str, vendor) Standardizes version strings based on vendor formats
--
-- @param version_str Version string to clean
-- @param vendor Vendor name to determine format
-- @return Cleaned version string
---
function extract_clean_version(version_str, vendor)
  if not version_str then return nil end

  -- Clean the input string first (remove null bytes, trim whitespace)
  local s = version_str:gsub("%z", ""):match("^%s*(.-)%s*$")
  if s == "" then return nil end

  -- Normalize vendor casing for matching
  local v = vendor and vendor:lower() or nil

  -- Helper: map 3 digits like "369" -> "3.6.9"
  local function ddd_to_semver(ddd)
    if not ddd or #ddd ~= 3 then return nil end
    return string.format("%s.%s.%s", ddd:sub(1,1), ddd:sub(2,2), ddd:sub(3,3))
  end

  -- ======================
  -- Vendor-targeted rules
  -- ======================

  -- DCMTK / OFFIS
  if v == "dcmtk" or s:find("DCMTK", 1, true) or s:find("OFFIS", 1, true) then
    -- OFFIS_DCMTK_369 / DCMTK_362 / with optional separators
    local a,b,c = s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk].-[ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    a,b,c = s:match("[Dd][Cc][Mm][Tt][Kk][ _-]?(%d)%.?(%d)%.?(%d)")
    if a and b and c then return string.format("%s.%s.%s", a,b,c) end

    -- DCMTK-3.6.8 / OFFIS_DCMTK_3.6.9
    local sem = s:match("[Dd][Cc][Mm][Tt][Kk][%s_%-/]*([%d]+%.%d+%.%d+)")
              or s:match("[Oo][Ff][Ff][Ii][Ss].-[Dd][Cc][Mm][Tt][Kk][%s_%-/]*([%d]+%.%d+%.%d+)")
    if sem then return sem end

    -- Raw 3-digit only when we already believe it's DCMTK
    local ddd = s:match("(%d%d%d)")
    if ddd then
      local semv = ddd_to_semver(ddd)
      if semv then return semv end
    end
  end

  -- pynetdicom
  if v == "pynetdicom" or s:find("PYNETDICOM") or s:lower():find("pynetdicom") then
    -- PYNETDICOM_210
    local ddd = s:match("PYNETDICOM[_-](%d%d%d)$")
    if ddd then
      local semv = ddd_to_semver(ddd)
      if semv then return semv end
    end
    -- pynetdicom/2.1.1 or pynetdicom 2.0.2 or PYNETDICOM 1.5.0
    local sem = s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s/:-]+([%d]+%.%d+%.%d+)")
             or s:match("[Pp][Yy][Nn][Ee][Tt][Dd][Ii][Cc][Oo][Mm][%s/:-]+([%d]+%.%d+)")
    if sem then return sem end
  end

  -- dcm4che
  if v == "dcm4che" or s:lower():find("dcm4che") then
    local sem = s:match("dcm4che[%w-]*[%s/:-]+([%d]+%.%d+%.%d+)")
    if sem then return sem end
  end

  -- Orthanc
  if v == "orthanc" or s:lower():find("orthanc") then
    local sem = s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+%.%d+)")
             or s:match("[Oo]rthanc[%s%-/]*[vV]?([%d]+%.%d+)")
    if sem then return sem end
  end

  -- OsiriX / Horos
  if v == "osirix" or v == "horos" or s:lower():find("osirix") or s:lower():find("horos") then
    local sem = s:match("[vV]([%d]+%.%d+%.%d+)")
             or s:match("([%d]+%.%d+%.%d+)")
             or s:match("([%d]+%.%d+)")
    if sem then return sem end
  end

  -- ClearCanvas
  if v == "clearcanvas" or s:find("ClearCanvas") then
    -- Prefer Major.Minor.Build if present (e.g., ClearCanvas_2.0.12345.37893 -> 2.0.12345)
    local maj, min, build = s:match("ClearCanvas[_-](%d+)%.(%d+)%.(%d+)")
    if maj and min and build then
      return string.format("%s.%s.%s", maj, min, build)
    end
    -- Fallback to Major.Minor
    maj, min = s:match("ClearCanvas[_-](%d+)%.(%d+)")
    if maj and min then
      return string.format("%s.%s", maj, min)
    end
    -- Or any semver present
    local sem = s:match("([%d]+%.%d+%.%d+)") or s:match("([%d]+%.%d+)")
    if sem then return sem end
  end

  -- ======================
  -- Generic fallbacks
  -- ======================

  -- Try standard X.Y.Z first
  local sem = s:match("(%d+%.%d+%.%d+)")
  if sem then return sem end

  -- Then X.Y
  sem = s:match("(%d+%.%d+)")
  if sem then return sem end

  -- As a very last resort, if vendor strongly hints DCMTK and we only have 3 digits anywhere
  if v == "dcmtk" then
    local ddd = s:match("(%d%d%d)")
    if ddd then
      local semv = ddd_to_semver(ddd)
      if semv then return semv end
    end
  end

  -- Nothing matched; return cleaned original so caller can still display something
  stdnse.debug2("extract_clean_version: no pattern matched for '%s' (vendor='%s')", s, v or "nil")
  return s
end


---
-- associate(host, port) Attempts to associate to a DICOM Service Provider by sending an A-ASSOCIATE request.
--
-- @param host Host object
-- @param port Port object
-- @param calling_aet Optional Calling Application Entity Title override
-- @param called_aet Optional Called Application Entity Title override
-- @return (status, dcm_or_error, version, vendor) If status is true, version and vendor info is returned.
--                                                If status is false, dcm_or_error is the error message.
---
function associate(host, port, calling_aet, called_aet)
  local status, dcm = start_connection(host, port)
  if status == false then
    return false, dcm -- dcm contains the error message from start_connection
  end

  -- ===== helpers scoped to this function (no external deps) =====
  local function ul_item(item_type, value_bytes)
    return string.pack(">B B I2", item_type, 0x00, #value_bytes) .. value_bytes
  end
  local function item_application_context(uid) return ul_item(0x10, uid) end
  local function item_abstract_syntax(uid)    return ul_item(0x30, uid) end
  local function item_transfer_syntax(uid)    return ul_item(0x40, uid) end
  local function item_presentation_context(pc_id, abstract_uid, transfer_uid)
    -- For RQ, result/ reason byte must be 0x00
    local header  = string.pack(">B B B B", pc_id, 0x00, 0x00, 0x00)
    local payload = header .. item_abstract_syntax(abstract_uid) .. item_transfer_syntax(transfer_uid)
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
  -- =============================================================

  -- Variables to hold results from pcall
  local success, pcall_ret1, pcall_ret2, pcall_ret3, pcall_ret4

  success, pcall_ret1, pcall_ret2, pcall_ret3, pcall_ret4 = pcall(function()
    -- Build A-ASSOCIATE-RQ items properly (no magic lengths)
    local application_context_name = "1.2.840.10008.3.1.1.1"   -- Application Context Name
    local abstract_syntax_name     = "1.2.840.10008.1.1"       -- Verification SOP Class
    local transfer_syntax_name     = "1.2.840.10008.1.2"       -- Implicit VR Little Endian

    local called_ae_title_val  = pad16(called_aet  or stdnse.get_script_args("dicom.called_aet")  or "ANY-SCP")
    local calling_ae_title_val = pad16(calling_aet or stdnse.get_script_args("dicom.calling_aet") or "ECHOSCU")

    -- Identify ourselves (client); using DCMTK-style identifiers is fine for a scanner client
    local implementation_id      = "1.2.276.0.7230010.3.0.3.6.2"
    local implementation_version = "OFFIS_DCMTK_362"
    local max_pdu_len            = 16384

    local application_context  = item_application_context(application_context_name)
    local presentation_context = item_presentation_context(1, abstract_syntax_name, transfer_syntax_name)
    local userinfo_context     = item_user_information(implementation_id, implementation_version, max_pdu_len)

    -- Fixed part of A-ASSOCIATE-RQ:
    -- protocol version (I2=0x0001), reserved (I2=0),
    -- called AE (16), calling AE (16), 32 reserved zero bytes
    local fixed = string.pack(">I2 I2 c16 c16 c32",
      0x0001, 0x0000, called_ae_title_val, calling_ae_title_val, string.rep("\0", 32))

    local assoc_body = fixed .. application_context .. presentation_context .. userinfo_context

    local header_ok, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_body)
    if header_ok == false then error("Failed to encode PDU header: " .. header) end
    local assoc_request = header .. assoc_body

    stdnse.debug2("PDU len minus header:%d", #assoc_request - #header)
    if #assoc_request < MIN_SIZE_ASSOC_REQ then
      error(string.format("ASSOCIATE request PDU must be at least %d bytes and we tried to send %d.",
            MIN_SIZE_ASSOC_REQ, #assoc_request))
    end

    local send_status, send_err = send(dcm, assoc_request)
    if not send_status then
      stdnse.debug1("DICOM Associate: send() failed immediately inside pcall. Error: %s", tostring(send_err))
      error(string.format("Couldn't send ASSOCIATE request:%s", send_err))
    else
      stdnse.debug1("DICOM Associate: send() call completed successfully inside pcall.")
    end

    local receive_status, response_data = receive(dcm)
    if not receive_status then error(string.format("Couldn't read ASSOCIATE response:%s", response_data)) end

    if #response_data < MIN_HEADER_LEN then error("Received response too short for PDU header") end
    local resp_type, _, resp_length = string.unpack(">B B I4", response_data)
    stdnse.debug1("PDU Type:%d Length:%d", resp_type, resp_length)

    if resp_type ~= PDU_CODES["ASSOCIATE_ACCEPT"] then
      if resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
        stdnse.debug1("ASSOCIATE REJECT message found!")
        error("ASSOCIATE REJECT received")
      else
        stdnse.debug1("Received unexpected PDU type: %d", resp_type)
        error("Received unexpected response PDU type")
      end
    end

    stdnse.debug1("ASSOCIATE ACCEPT message found! Parsing User Information.")
    local received_version_str, received_uid_str = parse_implementation_version(response_data)
    local impl_version_name = received_version_str  -- raw DICOM Implementation Version Name

    local parsed_vendor, parsed_clean_version = nil, nil

    if received_uid_str then
      local vendor_result = identify_vendor_from_uid(received_uid_str)
      if vendor_result then parsed_vendor = vendor_result end

      if received_version_str then
        parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
        stdnse.debug1("Using received_version_str ('%s') for cleaning. Result: %s",
                      received_version_str, parsed_clean_version or "nil")
      end
    elseif received_version_str then
      local guess_vendor
      local v = (received_version_str or ""):lower()
      if     v:find("dcm4che",   1, true) then guess_vendor = "dcm4che"
      elseif v:find("dcmtk",     1, true) then guess_vendor = "DCMTK"
      elseif v:find("pynetdicom",1, true) then guess_vendor = "pynetdicom"
      elseif v:find("orthanc",   1, true) then guess_vendor = "Orthanc"
      end
      parsed_clean_version = extract_clean_version(received_version_str, guess_vendor)
      parsed_vendor = guess_vendor
      stdnse.debug1("Only received_version_str ('%s') available for cleaning. Result: %s",
                    received_version_str, parsed_clean_version or "nil")
    end

    stdnse.debug1("Parsed values - Clean Version: %s, Raw UID: %s, Vendor: %s",
                  parsed_clean_version or "nil",
                  received_uid_str or "nil",
                  parsed_vendor or "nil")

    -- final_version is either cleaned, or falls back to the raw Implementation Version Name
    local final_version = parsed_clean_version or impl_version_name

    -- Return: final_version, vendor, uid_str, impl_version_name (raw)
    return final_version, parsed_vendor, received_uid_str, impl_version_name
  end) -- pcall

  -- Always close socket
  if dcm and dcm['socket'] then
    stdnse.debug1("Closing socket after association attempt.")
    dcm['socket']:close()
  end

  if not success then
    local err_msg = pcall_ret1 and tostring(pcall_ret1) or "Unknown error during association pcall"
    stdnse.debug1("Error during association (pcall failed): %s", err_msg)
    return false, err_msg
  else
    local final_version     = pcall_ret1
    local final_vendor      = pcall_ret2
    local final_uid         = pcall_ret3
    local impl_version_name = pcall_ret4

    stdnse.debug1("Association successful. Final Version: %s, Vendor: %s",
                  final_version or "nil", final_vendor or "nil")

    return true, nil, final_version, final_vendor, final_uid, impl_version_name
  end
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
end

function extract_uid_root(uid)
  if not uid then return nil end
  local trimmed = uid:gsub("%z",""):match("^%s*(.-)%s*$")
  if trimmed == "" then return nil end
  return trimmed:match("^([%d%.]+)%.[^%.]+$") or trimmed
end

return _ENV