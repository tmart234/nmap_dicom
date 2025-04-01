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

-- Define vendor UIDs lookup table with patterns and version indicators
local VENDOR_UID_PATTERNS = {
  {"^1%.2%.276%.0%.7230010%.3%.0%.3%.6%.(%d+)", "DCMTK", true},    -- DCMTK with version extraction
  {"^1%.2%.276%.0%.7230010%.3%.0%.3%.6",         "DCMTK"},          -- General DCMTK
  {"^1%.4%.3%.6%.1%.4%.1%.78293%.3%.1",          "Orthanc"},        -- Orthanc
  {"^1%.3%.46%.670589%.50%.1%.4",                "Conquest"},       -- Conquest PACS
  {"^1%.2%.40%.0%.13%.1%.1",                     "DCM4CHE"},        -- dcm4chee
  {"^1%.2%.840%.113619%.6%.96",                  "GE Healthcare"},  -- GE
  {"^1%.2%.840%.113619%.6%.105",                 "Philips"},        -- Philips
  {"^1%.3%.12%.2%.1107%.5%.99",                  "Siemens Syngo"},  -- Siemens
  {"^1%.3%.12%.2%.1107%.5%.8",                   "Siemens"},        -- Other Siemens
  {"^1%.2%.840%.10008%.5%.1%.4",                 "DICOM Standard"}, -- DICOM Standard
  {"^1%.2%.124%.113532%.3%.1",                   "Merge Healthcare"},-- Merge PACS
  {"^1%.2%.826%.0%.1%.3680043%.9%.3%.9%.1",      "ClearCanvas"},    -- ClearCanvas
  {"^1%.2%.840%.114257%.1%.15",                  "Horos"},          -- Horos
  {"^1%.2%.826%.0%.1%.3680043%.8%.1057%.1%.2%.%d+%.%d+$", "OsiriX"},-- OsiriX
  {"^1%.2%.392%.200036%.9%.1%.1%.1",             "FujiFilm"},       -- FujiFilm
  {"^1%.2%.840%.114340%.2%.1",                   "Agfa"},           -- Agfa
  {"^1%.2%.840%.113704%.7%.1%.1%.1%.1%.1",       "Carestream"}      -- Carestream
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

  local header = string.pack("<B >B I4",
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

  -- Minimum length check (PDU header + fixed AC fields + User Info item header)
  -- PDU Header(6) + ProtoVer(2) + Reserved(2) + CalledAE(16) + CallingAE(16) + Reserved(32) + AppCtxItemHeader(4) = 78
  -- Let's be slightly less strict, require at least enough for User Info Item header (approx 72 based on request structure)
  if data_len < 72 then
    stdnse.debug1("Response too short for reliable User Information parsing: %d bytes", data_len)
    return nil, nil
  end

  -- *** Find User Information item (0x50) ***
  -- It should follow the fixed association parameters (68 bytes in request, similar in accept)
  local userinfo_marker = string.char(0x50, 0x00)
  -- Start searching after the fixed header part (approx 68 bytes) for efficiency, but search whole string for robustness.
  local userinfo_start = data:find(userinfo_marker, 60, true) -- Start search around where it should be

  if not userinfo_start then
      stdnse.debug1("User Information item (0x50 0x00) marker not found.")
      return nil, nil -- Can't proceed without User Info item
  end
  stdnse.debug2("Found User Information marker at offset %d", userinfo_start)

  -- Check if there's enough data for User Info Length field (2 bytes)
  if userinfo_start + 3 > data_len then
     stdnse.debug1("Not enough data for User Information length at offset %d.", userinfo_start)
     return nil, nil
  end

  -- Get User Info Length
  local _, userinfo_len = string.unpack(">I2", data, userinfo_start + 2) -- Length is 2 bytes after marker
  local userinfo_payload_start = userinfo_start + 4
  local userinfo_payload_end = userinfo_start + 3 + userinfo_len
  stdnse.debug2("User Information item length: %d. Payload offsets: %d - %d", userinfo_len, userinfo_payload_start, userinfo_payload_end)

  -- Validate User Info boundaries
  if userinfo_payload_end > data_len then
     stdnse.debug1("User Information length (%d) exceeds data boundary (%d). Truncating parse range.", userinfo_len, data_len)
     userinfo_payload_end = data_len
  end
  if userinfo_payload_start > userinfo_payload_end then
      stdnse.debug1("User Information payload start offset is beyond its end offset. Cannot parse sub-items.")
      return nil, nil
  end

  -- *** Iterate through sub-items within User Information ***
  local offset = userinfo_payload_start
  while offset < userinfo_payload_end - 3 do -- Need at least 4 bytes for Type, Reserved, Length
    local sub_type = string.byte(data, offset + 1)
    local reserved_byte = string.byte(data, offset + 2)

    -- Expect Reserved byte to be 0x00
    if reserved_byte ~= 0x00 then
        stdnse.debug2("Sub-item at offset %d has non-zero reserved byte (0x%02X). Skipping item (assuming fixed length or error).", offset, reserved_byte)
        -- This case is tricky. We don't know the length. Advance by a minimum? For now, stop parsing sub-items.
        break
    end

    -- Check for sub-item length field
    if offset + 3 > userinfo_payload_end then
        stdnse.debug1("Not enough data for sub-item length at offset %d", offset)
        break
    end

    local _, sub_length = string.unpack(">I2", data, offset + 2) -- Length starts 2 bytes after type
    local sub_value_start = offset + 4
    local sub_value_end = offset + 3 + sub_length
    stdnse.debug2("Found sub-item type 0x%02X, length %d at offset %d. Value range: %d - %d", sub_type, sub_length, offset, sub_value_start, sub_value_end)

    -- Validate sub-item value boundaries
    if sub_value_end > userinfo_payload_end then
        stdnse.debug1("Sub-item (type 0x%02X) length %d exceeds User Info boundary (%d) at offset %d. Stopping sub-item parse.", sub_type, sub_length, userinfo_payload_end, offset)
        break
    end
    if sub_value_start > sub_value_end then
        stdnse.debug1("Sub-item (type 0x%02X) value start offset %d is beyond end offset %d. Skipping item.", sub_type, sub_value_start, sub_value_end)
        offset = sub_value_end + 1 -- Move to where next item should be
        goto continue_loop -- Use goto for clarity to continue outer while loop
    end

    -- Extract and clean value if length is positive
    if sub_length > 0 then
        -- Sanity check length (e.g., max 64 for UIDs/Versions)
        if sub_length > 128 then -- Increased limit slightly
             stdnse.debug1("Sub-item (type 0x%02X) length %d seems excessive (>128) at offset %d. Skipping value extraction.", sub_type, sub_length, offset)
        else
            local value_raw = data:sub(sub_value_start, sub_value_end)
            local value_cleaned = value_raw:gsub("%z", ""):gsub("^%s*", ""):gsub("%s*$", "") -- Trim whitespace and nulls

            if sub_type == 0x52 then -- Implementation Class UID
                if not uid then -- Only take the first one found
                    uid = value_cleaned
                    stdnse.debug1("Extracted UID: '%s'", uid)
                end
            elseif sub_type == 0x55 then -- Implementation Version Name
                if not version then -- Only take the first one found
                    version = value_cleaned
                    stdnse.debug1("Extracted Version: '%s'", version)
                end
            -- Add other user info sub-types here if needed (e.g., 0x51 Max PDU Length)
            end
        end
    else
         stdnse.debug2("Sub-item (type 0x%02X) has zero length.", sub_type)
    end

    -- Move offset to the beginning of the next sub-item
    offset = sub_value_end + 1

    ::continue_loop::
  end -- while offset

  stdnse.debug1("Finished parsing User Info sub-items. Final raw values - Version: '%s', UID: '%s'", version or "nil", uid or "nil")
  return version, uid
end

---
-- identify_vendor_from_uid(uid) Gets vendor name and version from the UID using pattern matching
--
-- @param uid Implementation UID string
-- @return vendor Vendor name or nil if unknown
-- @return version_part Optional version part extracted from the UID
---
function identify_vendor_from_uid(uid)
  if not uid then return nil, nil end
  
  -- Clean up UID string
  uid = uid:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "")
  
  -- Special case for short UIDs that might be truncated
  if #uid < 5 and uid:match("^1%.2") then
    -- This is likely a truncated DICOM UID, assume it's DCMTK
    return "DCMTK", nil
  end
  
  -- Check against patterns
  for _, pattern_info in ipairs(VENDOR_UID_PATTERNS) do
    local pattern, vendor, extract_version = pattern_info[1], pattern_info[2], pattern_info[3]    
    -- Check if UID matches this pattern
    local match = {uid:match(pattern)}
    if #match > 0 then
      -- If this pattern contains version extraction
      if extract_version and match[1] then
        local version_part = match[1]
        return vendor, version_part
      end
      return vendor, nil
    end
  end
  
  return nil, nil
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
  
  -- DCMTK versions - Expanded to handle more formats
  if vendor == "DCMTK" or version_str:match("OFFIS_DCMTK") then
    -- Common DCMTK version format: OFFIS_DCMTK_362 -> 3.6.2
    local major, minor, patch = version_str:match("DCMTK_(%d)(%d+)(%d)")
    if major and minor and patch then
      return string.format("%s.%s.%s", major, minor, patch)
    end
    
    -- Alternative format: DCMTK_364
    major, minor, patch = version_str:match("DCMTK_(%d)(%d)(%d)")
    if major and minor and patch then
      return string.format("%s.%s.%s", major, minor, patch)
    end
    
    -- Handle incomplete version strings by directly checking for numbers
    if version_str:match("DCMTK") then
      -- If the version string contains DCMTK, try to extract just the numbers
      local version_numbers = version_str:match("DCMTK_(%d+)")
      if version_numbers and #version_numbers == 3 then
        local major = version_numbers:sub(1,1)
        local minor = version_numbers:sub(2,2)
        local patch = version_numbers:sub(3,3)
        return string.format("%s.%s.%s", major, minor, patch)
      end
    end
  end
  
  -- If the version contains "OFFIS" but we haven't matched it yet
  if version_str:match("OFFIS") then
    -- Try to extract any 3-digit sequence that might represent a version
    local version_numbers = version_str:match("(%d%d%d)")
    if version_numbers and #version_numbers == 3 then
      local major = version_numbers:sub(1,1)
      local minor = version_numbers:sub(2,2)
      local patch = version_numbers:sub(3,3)
      return string.format("%s.%s.%s", major, minor, patch)
    end
  end
  
  -- Remainder of the original function...
  -- Horos/OsiriX versions
  if vendor == "Horos" or vendor == "OsiriX" then
    -- Format: Horos-v3.3.6 or OsiriX-v9.0.2
    local ver = version_str:match("v(%d+%.%d+%.%d+)")
    if ver then
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
        return string.format("%s.%s.%s", major, minor, build)
      end
      return string.format("%s.%s", major, minor)
    end
  end
  
  -- Generic version detection: Try standard version format first
  local version = version_str:match("(%d+%.%d+%.%d+)")
  if version then
    return version
  end
  
  -- Try just major.minor format
  version = version_str:match("(%d+%.%d+)")
  if version then
    return version
  end
  
  -- If all else fails, return as is
  return version_str
end


---
---
-- associate(host, port) Attempts to associate to a DICOM Service Provider by sending an A-ASSOCIATE request.
--
-- @param host Host object
-- @param port Port object
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

  -- *** Ensure socket closure using try/finally pattern ***
  local assoc_request, header, err, resp_type, resp_length, version_str, uid_str, vendor, clean_version
  status, err = stdnse.catch(function()

    -- (Keep the existing code here to build application_context, presentation_context, userinfo_context)
    local application_context_name = "1.2.840.10008.3.1.1.1"
    application_context = string.pack(">B B s2", 0x10, 0x0, application_context_name)

    local abstract_syntax_name = "1.2.840.10008.1.1"
    local transfer_syntax_name = "1.2.840.10008.1.2"
    presentation_context = string.pack(">B B I2 B B B B B B s2 B B s2", 0x20, 0x0, 0x2e, 0x1, 0x0,0x0,0x0, 0x30, 0x0, abstract_syntax_name, 0x40, 0x0, transfer_syntax_name)

    local implementation_id = "1.2.276.0.7230010.3.0.3.6.2" -- Note: This is hardcoded client info, not server's
    local implementation_version = "OFFIS_DCMTK_362"      -- Note: This is hardcoded client info, not server's
    userinfo_context = string.pack(">B B I2 B B I2 I4 B B s2 B B s2", 0x50, 0x0, 0x3a, 0x51, 0x0, 0x04, 0x4000, 0x52, 0x0, implementation_id, 0x55, 0x0, implementation_version)
    -- (End of building context)

    local called_ae_title = called_aet or stdnse.get_script_args("dicom.called_aet") or "ANY-SCP"
    local calling_ae_title = calling_aet or stdnse.get_script_args("dicom.calling_aet") or "ECHOSCU"
    if #called_ae_title > 16 or #calling_ae_title > 16 then
      error("Calling/Called Application Entity Title must be less than 16 bytes")
    end
    called_ae_title = ("%-16s"):format(called_ae_title)
    calling_ae_title = ("%-16s"):format(calling_ae_title)

    -- ASSOCIATE request body
    assoc_request = string.pack(">I2 I2 c16 c16 c32", 0x1, 0x0, called_ae_title, calling_ae_title, "")
                       .. application_context
                       .. presentation_context
                       .. userinfo_context

    local header_status
    header_status, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_request)
    if header_status == false then
      error("Failed to encode PDU header: " .. header)
    end

    assoc_request = header .. assoc_request

    stdnse.debug2("PDU len minus header:%d", #assoc_request-#header)
    if #assoc_request < MIN_SIZE_ASSOC_REQ then
      error(string.format("ASSOCIATE request PDU must be at least %d bytes and we tried to send %d.", MIN_SIZE_ASSOC_REQ, #assoc_request))
    end

    local send_status, send_err = send(dcm, assoc_request)
    if send_status == false then
      error(string.format("Couldn't send ASSOCIATE request:%s", send_err))
    end

    local receive_status, receive_data = receive(dcm)
    if receive_status == false then
      error(string.format("Couldn't read ASSOCIATE response:%s", receive_data))
    end
    err = receive_data -- Assign received data to err for parsing

    -- Check minimum length before unpacking header
    if #err < MIN_HEADER_LEN then
      error("Received response too short for PDU header")
    end
    resp_type, _, resp_length = string.unpack(">B B I4", err) -- Unpack header
    stdnse.debug1("PDU Type:%d Length:%d", resp_type, resp_length)

    -- Check if it's an ACCEPT PDU
    if resp_type ~= PDU_CODES["ASSOCIATE_ACCEPT"] then
      if resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
         stdnse.debug1("ASSOCIATE REJECT message found!")
         -- TODO: Optionally parse reject reason/source/diagnostic here
         error("ASSOCIATE REJECT received")
      else
         stdnse.debug1("Received unexpected PDU type: %d", resp_type)
         error("Received unexpected response PDU type")
      end
    end

    -- *** PARSE using dedicated function ***
    stdnse.debug1("ASSOCIATE ACCEPT message found! Parsing User Information.")
    version_str, uid_str = parse_implementation_version(err) -- Pass the *entire* received PDU

    -- Identify Vendor and Clean Version
    if uid_str then
      local vendor_result, version_part_from_uid = identify_vendor_from_uid(uid_str)
      if vendor_result then vendor = vendor_result end

      if version_part_from_uid then
         clean_version = extract_clean_version(version_part_from_uid, vendor)
      elseif version_str then
         clean_version = extract_clean_version(version_str, vendor)
      end
    elseif version_str then
       -- Fallback if UID wasn't found/parsed
       if version_str:match("OFFIS_DCMTK") or version_str:match("DCMTK") then
           vendor = "DCMTK"
       end
       clean_version = extract_clean_version(version_str, vendor)
    end

    stdnse.debug1("Final values - Version: %s, UID: %s, Vendor: %s",
                  clean_version or "nil",
                  uid_str or "nil",
                  vendor or "nil")

    -- Success, return parsed info
    return true, nil, clean_version, vendor -- Return structure matches original intent

  end) -- end catch

  -- *** Finally block: close the socket ***
  if dcm and dcm['socket'] then
    dcm['socket']:close()
  end

  -- Check status of the try block
  if not status then
    -- An error occurred inside the catch block
    stdnse.debug1("Error during association: %s", err)
    return false, err -- Return the error message
  end

  -- If catch block succeeded, return the values captured inside it
  return status, nil, clean_version, vendor -- Status is true here
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

