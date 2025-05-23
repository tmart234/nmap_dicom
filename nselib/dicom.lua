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

-- Define vendor UIDs lookup table with patterns (matching base prefixes only)
local VENDOR_UID_PATTERNS = {
  {"^1%.2%.276%.0%.7230010%.3%.0",           "DCMTK"},          -- General DCMTK base
  {"^1%.4%.3%.6%.1%.4%.1%.78293%.3%.1",       "Orthanc"},        -- Orthanc base
  {"^1%.3%.46%.670589%.50%.1%.4",           "Conquest"},       -- Conquest PACS base
  {"^1%.2%.40%.0%.13%.1%.3",               "DCM4CHE"}, 
  {"^1%.2%.826%.0%.1%.3680043%.9%.3811",    "pynetdicom"},       -- dcm4chee base
  {"^1%.2%.840%.113619%.2%.55",           "GE Healthcare"},  -- GE Healthcare base
  {"^1%.2%.840%.113619%.6%.96",           "GE Healthcare"},  -- GE base
  {"^1%.2%.840%.113619%.6%.105",          "GE Healthcare"},  -- GE base
  {"^1%.3%.12%.2%.1107%.5%.99",           "Siemens Syngo"},  -- Siemens Syngo base
  {"^1%.3%.12%.2%.1107%.5%.8",            "Siemens"},        -- Other Siemens base
  {"^1%.2%.840%.10008%.5%.1%.4",          "DICOM Standard"}, -- DICOM Standard base (SOP Class related)
  {"^1%.2%.124%.113532%.3%.1",            "Merge Healthcare"},-- Merge PACS base
  {"^1%.2%.826%.0%.1%.3680043%.9%.3%.9%.1", "ClearCanvas"},    -- ClearCanvas base
  {"^1%.2%.840%.114257%.1%.15",           "Horos"},          -- Horos base
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.1%.2", "OsiriX"},       -- OsiriX base prefix
  {"^1%.2%.392%.200036%.9%.1%.1%.1",       "FujiFilm"},       -- FujiFilm base
  {"^1%.2%.840%.114340%.2%.1",            "Agfa"},           -- Agfa base
  {"^1%.2%.840%.113704%.7%.1%.1%.1%.1%.1", "Carestream"},     -- Carestream base
  {"^1%.2%.826%.0%.1%.3680043%.9%.3",       "DICOM Standard"}, -- Or maybe generic UK NHS software?
  {"^1%.3%.6%.1%.4%.1%.19376",             "Mayo Clinic"}    -- Mayo Clinic base
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
  local status, err
  dcm['socket'] = nmap.new_socket()

  status, err = dcm['socket']:connect(host, port, "tcp")

  if(status == false) then
    return false, "DICOM: Failed to connect to host: " .. err
  end

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
-- receive(dcm) Reads DICOM packets over an established socket
--
-- @param dcm DICOM object
-- @return (status, data) Returns data if status true, otherwise data is the error message.
---
function receive(dcm)
  local status, data = dcm['socket']:receive()
  if status == false then
    return false, data
  end
  stdnse.debug1("DICOM: receive() read %d bytes", #data)
  return true, data
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
  if not(type(pdu_type)) == "number" then
    return false, "PDU Type must be an unsigned integer. Range:0-7"
  end
  if not(type(length)) == "number" then
    return false, "Length must be an unsigned integer."
  end

  local header = string.pack(">B B I4",
                            pdu_type, -- PDU Type ( 1 byte - unsigned integer in Big Endian )
                            0,        -- Reserved section ( 1 byte that should be set to 0x0 )
                            length)   -- PDU Length ( 4 bytes - unsigned integer in Little Endian)
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
  local userinfo_start = data:find(userinfo_marker, 65, true)

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
                       local _, max_len = string.unpack(">I4", value_raw)
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

  -- Clean up UID string (remove null bytes, trim whitespace)
  uid = uid:gsub("%z", ""):gsub("^%s*", ""):gsub("%s*$", "")

  -- Check against patterns
  for _, pattern_info in ipairs(VENDOR_UID_PATTERNS) do
    local pattern_regex, vendor = pattern_info[1], pattern_info[2]

    --[[
    -- OLD METHOD using string.match (Requires pattern to match whole string implicitly)
    if uid:match(pattern_regex) then
      stdnse.debug2("UID '%s' matched pattern '%s' for vendor '%s'", uid, pattern_regex, vendor)
      return vendor -- Return only the vendor name
    end
    --]]

    -- *** NEW METHOD using string.find to check prefix ***
    -- Use string.find anchored at the beginning (position 1).
    -- The 'true' argument disables pattern matching (magic characters) for the find itself,
    -- treating the pattern string literally *after* we manually handle '^' and '%.'.
    -- We remove the '^' anchor as string.find handles the start position.
    -- We need to convert '%. 'back to '.' for the literal find.
    local literal_prefix = pattern_regex:gsub("^%^", "") -- Remove leading ^ anchor
    literal_prefix = literal_prefix:gsub("%%%.", ".")   -- Convert escaped %. back to literal .

    -- Check if the uid STARTS WITH the literal_prefix
    if uid:find(literal_prefix, 1, true) == 1 then
      stdnse.debug2("UID '%s' matched pattern prefix '%s' (literal: '%s') for vendor '%s'", uid, pattern_regex, literal_prefix, vendor)
      return vendor -- Return only the vendor name
    end
    -- *** END NEW METHOD ***
  end

  stdnse.debug2("UID '%s' did not match any known vendor patterns.", uid)
  return nil -- No match found
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
  version_str = version_str:gsub("%z", ""):gsub("^%s*", ""):gsub("%s*$", "")

  -- DCMTK versions - Expanded to handle more formats
  -- Check vendor hint OR if the string contains DCMTK identifiers
  if vendor == "DCMTK" or version_str:match("OFFIS_DCMTK") or version_str:match("DCMTK") then
    -- Handle OFFIS_DCMTK_369 format -> 3.6.9
    local major, minor, patch = version_str:match("OFFIS_DCMTK_(%d)(%d)(%d)")
    if major and minor and patch then
      stdnse.debug1("Matched OFFIS_DCMTK_ddd format: %s.%s.%s", major, minor, patch)
      return string.format("%s.%s.%s", major, minor, patch)
    end

    -- Handle DCMTK_362 format -> 3.6.2 (Adjusted pattern)
    major, minor, patch = version_str:match("DCMTK_(%d)(%d)(%d)") -- Removed '+' from middle digit group
    if major and minor and patch then
      stdnse.debug1("Matched DCMTK_ddd format: %s.%s.%s", major, minor, patch)
      return string.format("%s.%s.%s", major, minor, patch)
    end

    -- Handle just 3 digits if other patterns failed (e.g., if only "369" was passed somehow)
    if #version_str == 3 and version_str:match("^(%d)(%d)(%d)$") then
        major, minor, patch = version_str:match("^(%d)(%d)(%d)$")
        if major and minor and patch then
            stdnse.debug1("Matched raw ddd format: %s.%s.%s", major, minor, patch)
            return string.format("%s.%s.%s", major, minor, patch)
        end
    end
  end

  -- If the version contains "OFFIS" but didn't match specific DCMTK patterns above
  if vendor == "DCMTK" and version_str:match("OFFIS") then -- Added vendor check for safety
    -- Try to extract any 3-digit sequence
    local version_numbers = version_str:match("(%d%d%d)")
    if version_numbers and #version_numbers == 3 then
      local major = version_numbers:sub(1,1)
      local minor = version_numbers:sub(2,2)
      local patch = version_numbers:sub(3,3)
      stdnse.debug1("Matched generic OFFIS ddd format: %s.%s.%s", major, minor, patch)
      return string.format("%s.%s.%s", major, minor, patch)
    end
  end

  -- Horos/OsiriX versions
  if vendor == "Horos" or vendor == "OsiriX" then
    -- Format: Horos-v3.3.6 or OsiriX-v9.0.2
    local ver = version_str:match("[vV](%d+%.%d+%.%d+)") -- Allow V or v
    if ver then
        stdnse.debug1("Matched Horos/OsiriX format: %s", ver)
        return ver
    end
      -- Try matching without 'v' prefix as well
      ver = version_str:match("(%d+%.%d+%.%d+)")
      if ver then
        stdnse.debug1("Matched Horos/OsiriX numeric format: %s", ver)
        return ver
      end
  end

  -- ClearCanvas versions
  if vendor == "ClearCanvas" then
    -- Format: ClearCanvas_2.0.12345.37893
    local major, minor = version_str:match("ClearCanvas_(%d+)%.(%d+)")
    if major and minor then
      local build = version_str:match("ClearCanvas_%d+%.%d+%.(%d+)")
      if build then
        stdnse.debug1("Matched ClearCanvas format (Major.Minor.Build): %s.%s.%s", major, minor, build)
        return string.format("%s.%s.%s", major, minor, build)
      end
      stdnse.debug1("Matched ClearCanvas format (Major.Minor): %s.%s", major, minor)
      return string.format("%s.%s", major, minor)
    end
  end

  if vendor == "pynetdicom" then
    -- *** ADDED BLOCK for PYNETDICOM_ddd format (e.g., PYNETDICOM_210) ***
    local digits = version_str:match("PYNETDICOM_(%d%d%d)$")
    if digits and #digits == 3 then
        local major = digits:sub(1,1)
        local minor = digits:sub(2,2)
        local patch = digits:sub(3,3)
        stdnse.debug1("Matched PYNETDICOM_ddd format: %s.%s.%s", major, minor, patch)
        return string.format("%s.%s.%s", major, minor, patch)
    end

    local major, minor, patch = version_str:match("PYNETDICOM_(%d)%.(%d)%.(%d)") -- Assuming dots if not _ddd
    if major and minor and patch then
      stdnse.debug1("Matched PYNETDICOM_X.Y.Z format: %s.%s.%s", major, minor, patch)
      return string.format("%s.%s.%s", major, minor, patch)
    end
    major, minor = version_str:match("PYNETDICOM_(%d)%.(%d)") -- Assuming dots if not _ddd
    if major and minor then
      stdnse.debug1("Matched PYNETDICOM_X.Y format: %s.%s", major, minor)
      return string.format("%s.%s", major, minor)
    end
  end

  if vendor == "DCM4CHE" then
    local version = version_str:match("dcm4che%-(%d+%.%d+%.%d+)")
    if version then
        stdnse.debug1("Matched dcm4che-X.Y.Z format: %s", version)
        return version
    end
  end

  -- Generic version detection: Try standard X.Y.Z format first
  local version = version_str:match("(%d+%.%d+%.%d+)")
  if version then
    stdnse.debug1("Matched generic X.Y.Z format: %s", version)
    return version
  end

  -- Try just X.Y format
  version = version_str:match("(%d+%.%d+)")
  if version then
    stdnse.debug1("Matched generic X.Y format: %s", version)
    return version
  end

  -- If all else fails, return the cleaned original string
  stdnse.debug1("No specific version format matched for '%s'. Returning as is.", version_str)
  return version_str
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
  local application_context = ""
  local presentation_context = ""
  local userinfo_context = ""

  local status, dcm = start_connection(host, port)
  if status == false then
    return false, dcm -- dcm contains the error message from start_connection
  end

  -- Variables to hold results from pcall
  local success, pcall_ret1, pcall_ret2, pcall_ret3
  local clean_version, vendor, uid_str -- Variables to hold final parsed values

  -- Wrap the main logic in pcall
  success, pcall_ret1, pcall_ret2, pcall_ret3 = pcall(function()
    -- Local variables for use inside pcall's function
    local assoc_request, header, err, resp_type, resp_length
    local received_version_str, received_uid_str
    local parsed_vendor, parsed_clean_version

    -- Build application_context, presentation_context, userinfo_context
    local application_context_name = "1.2.840.10008.3.1.1.1"
    application_context = string.pack(">B B s2", 0x10, 0x0, application_context_name)

    local abstract_syntax_name = "1.2.840.10008.1.1"
    local transfer_syntax_name = "1.2.840.10008.1.2"
    presentation_context = string.pack(">B B I2 B B B B B B s2 B B s2", 0x20, 0x0, 0x2e, 0x1, 0x0,0x0,0x0, 0x30, 0x0, abstract_syntax_name, 0x40, 0x0, transfer_syntax_name)

    local implementation_id = "1.2.276.0.7230010.3.0.3.6.2" -- Client info
    local implementation_version = "OFFIS_DCMTK_362"      -- Client info
    userinfo_context = string.pack(">B B I2 B B I2 I4 B B s2 B B s2", 0x50, 0x0, 0x3a, 0x51, 0x0, 0x04, 0x4000, 0x52, 0x0, implementation_id, 0x55, 0x0, implementation_version)

    local called_ae_title_val = called_aet or stdnse.get_script_args("dicom.called_aet") or "ANY-SCP"
    local calling_ae_title_val = calling_aet or stdnse.get_script_args("dicom.calling_aet") or "ECHOSCU"
    if #called_ae_title_val > 16 or #calling_ae_title_val > 16 then
      error("Calling/Called Application Entity Title must be less than 16 bytes")
    end
    called_ae_title_val = ("%-16s"):format(called_ae_title_val)
    calling_ae_title_val = ("%-16s"):format(calling_ae_title_val)

    -- ASSOCIATE request body
    assoc_request = string.pack(">I2 I2 c16 c16 c32", 0x1, 0x0, called_ae_title_val, calling_ae_title_val, "")
                       .. application_context
                       .. presentation_context
                       .. userinfo_context

    local header_status
    header_status, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_request)
    if header_status == false then error("Failed to encode PDU header: " .. header) end
    assoc_request = header .. assoc_request

    stdnse.debug2("PDU len minus header:%d", #assoc_request-#header)
    if #assoc_request < MIN_SIZE_ASSOC_REQ then
      error(string.format("ASSOCIATE request PDU must be at least %d bytes and we tried to send %d.", MIN_SIZE_ASSOC_REQ, #assoc_request))
    end

    local send_status, send_err = send(dcm, assoc_request)
    if send_status == false then
      stdnse.debug1("DICOM Associate: send() failed immediately inside pcall. Error: %s", tostring(send_err))
      error(string.format("Couldn't send ASSOCIATE request:%s", send_err)) -- Re-throw error
    else
        stdnse.debug1("DICOM Associate: send() call completed successfully inside pcall.")
    end

    local receive_status, receive_data = receive(dcm)
    if receive_status == false then error(string.format("Couldn't read ASSOCIATE response:%s", receive_data)) end
    local response_data = receive_data

    if #response_data < MIN_HEADER_LEN then error("Received response too short for PDU header") end
    resp_type, _, resp_length = string.unpack(">B B I4", response_data)
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
    received_version_str, received_uid_str = parse_implementation_version(response_data)

    -- Initialize parsed_vendor and parsed_clean_version
    parsed_vendor = nil
    parsed_clean_version = nil -- This will hold the final cleaned version

    if received_uid_str then
        local vendor_result, version_part_from_uid = identify_vendor_from_uid(received_uid_str)
        if vendor_result then parsed_vendor = vendor_result end -- Assign vendor based on UID

        -- *** MODIFIED LOGIC: Prioritize full version string for cleaning ***
        if received_version_str then
            -- Clean the full string from field 0x55 if available
            parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
            stdnse.debug1("Using received_version_str ('%s') for cleaning. Result: %s", received_version_str, parsed_clean_version or "nil")
        elseif version_part_from_uid then
            -- Fallback to UID part only if full version string is missing
            parsed_clean_version = extract_clean_version(version_part_from_uid, parsed_vendor)
            stdnse.debug1("No received_version_str. Using version_part_from_uid ('%s') for cleaning. Result: %s", version_part_from_uid, parsed_clean_version or "nil")
        end
        -- *** END MODIFIED LOGIC ***

    elseif received_version_str then
       -- Only version string was available (no UID or UID didn't contain version info)
       -- Try to guess vendor=DCMTK if applicable based on string content
       if parsed_vendor == nil and (received_version_str:match("OFFIS_DCMTK") or received_version_str:match("DCMTK")) then
           parsed_vendor = "DCMTK"
       end
       parsed_clean_version = extract_clean_version(received_version_str, parsed_vendor)
       stdnse.debug1("Only received_version_str ('%s') available for cleaning. Result: %s", received_version_str, parsed_clean_version or "nil")
    end

    -- Final debug log before returning from pcall's function
    stdnse.debug1("Parsed values - Clean Version: %s, Raw UID: %s, Vendor: %s",
                  parsed_clean_version or "nil",
                  received_uid_str or "nil",
                  parsed_vendor or "nil")

    -- Return the results needed by the outer part of associate
    -- Order: clean_version, vendor, uid_str (uid_str might be useful later)
    return parsed_clean_version, parsed_vendor, received_uid_str

  end) -- end pcall

  -- *** Manual "finally" block: always close the socket ***
  if dcm and dcm['socket'] then
    stdnse.debug1("Closing socket after association attempt.")
    dcm['socket']:close()
  end

  -- Check the status returned by pcall
  if not success then
    -- An error occurred inside pcall. pcall_ret1 contains the error message/object.
    local err_msg = "Unknown error during association pcall"
    if pcall_ret1 ~= nil then
      err_msg = tostring(pcall_ret1)
    end
    stdnse.debug1("Error during association (pcall failed): %s", err_msg)
    return false, err_msg -- Return false and the safe error message
  else
    -- pcall succeeded. Assign the results returned by the function.
    clean_version = pcall_ret1 -- First value returned was clean_version
    vendor = pcall_ret2        -- Second value returned was vendor
    uid_str = pcall_ret3       -- Third value returned was uid_str

    stdnse.debug1("Association successful. Final Version: %s, Vendor: %s",
                  clean_version or "nil", vendor or "nil")

    -- Return true and the extracted info, matching the expected format:
    -- (status, dcm_or_error, version, vendor)
    return true, nil, clean_version, vendor
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

return _ENV

