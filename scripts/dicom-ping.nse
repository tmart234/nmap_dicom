--[[
Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.
It also detects if the server allows any called Application Entity Title or not.

The script responds with the message "Called AET check enabled" when the association request
is rejected due configuration. This value can be bruteforced using dicom-brute.

The UID tells you who made it (Vendor), the dedicated Version Name field tells you which version it is.

C-ECHO requests are commonly known as DICOM ping as they are used to test connectivity.
Normally, a 'DICOM ping' is formed as follows:
* Client -> A-ASSOCIATE request -> Server
* Server -> A-ASSOCIATE ACCEPT/REJECT -> Client
* Client -> C-ECHO request -> Server
* Server -> C-ECHO response -> Client
* Client -> A-RELEASE request -> Server
* Server -> A-RELEASE response -> Client

For this script we only send the A-ASSOCIATE request and look for the success code
in the response as it seems to be a reliable way of detecting DICOM servers.
]]

---
-- @usage nmap -p4242 --script dicom-ping <target>
-- @usage nmap -sV --script dicom-ping <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.ports=11114,11115 <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 4242/tcp open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   vendor: Orthanc
-- |_  version: 1.11.0
--
-- @xmloutput
-- <script id="dicom-ping" output="&#xa;  dicom: DICOM Service Provider discovered!&#xa;
--   config: Any AET is accepted (Insecure)&#xa;
--   vendor: Orthanc&#xa;
--   version: 1.11.0"><elem key="dicom">DICOM Service Provider discovered!</elem>
-- <elem key="config">Any AET is accepted (Insecure)</elem>
-- <elem key="vendor">Orthanc</elem>
-- <elem key="version">1.11.0</elem>
-- </script>
---

author = "Paulino Calderon <calderon()calderonpale.com>, Tyler M <tmart234()gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"

-- Helper function to parse the ports argument into a table of numbers
local function parse_ports_arg(ports_str)
  local ports_set = {}
  if not ports_str then return nil end
  -- Use gmatch to find sequences of digits, ignoring non-digits/commas
  for port_num_str in string.gmatch(ports_str, "%d+") do
    local port_num = tonumber(port_num_str)
    if port_num then
      ports_set[port_num] = true -- Use table as a set for quick lookup
    end
  end
  -- Check if any ports were actually parsed
  if next(ports_set) == nil then
    return nil -- Return nil if parsing resulted in an empty set (e.g., bad input)
  end
  return ports_set
end

portrule = function(host, port)
  -- Basic requirement: Port must be TCP and open.
  if not (port.protocol == "tcp" and port.state == "open") then
    return false
  end

  -- Check for specific ports passed via script argument (for testing)
  local ports_arg_str = stdnse.get_script_args("dicom-ping.ports")
  if ports_arg_str then
    local target_ports = parse_ports_arg(ports_arg_str)
    if target_ports and target_ports[port.number] then
      stdnse.debug(1, "dicom-ping: portrule returning true (matched port %d from script-arg 'dicom-ping.ports')", port.number)
      return true
    elseif target_ports then
      -- Argument was provided but didn't match this port, proceed to standard checks
      stdnse.debug(2, "dicom-ping: port %d not in ports specified by script-arg", port.number)
    else
      -- Argument was provided but couldn't be parsed meaningfully, proceed to standard checks
      stdnse.debug(1, "dicom-ping: could not parse 'dicom-ping.ports' argument: %s", ports_arg_str)
    end
  end
  -- If ports_arg_str was nil, we also proceed to standard checks

  -- Standard DICOM Check (for real-world use):
  -- Run if the port is a common DICOM port OR if Nmap detected the service as 'dicom'.
  -- Common ports: 104, 2345, 2761, 2762, 4242, 11112.
  if shortport.port_or_service({104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp")(host, port) then
    stdnse.debug(1, "dicom-ping: portrule returning true (matched standard port or 'dicom' service) for port %d", port.number)
    return true
  end

  stdnse.debug(1, "dicom-ping: portrule returning false for port %d", port.number)
  return false
end

action = function(host, port)
  stdnse.debug(1, "dicom-ping: ACTION function started for %s:%d", host.ip, port.number)
  local output = stdnse.output_table()

  local called_aet_arg = stdnse.get_script_args("dicom.called_aet")

  -- Expecting: status, err, version, vendor, uid (uid may be nil if peer didn't send it)
  local dcm_status, err, version, vendor, uid = dicom.associate(host, port, nil, called_aet_arg)

  -- association rejection handling
  if dcm_status == false then
    stdnse.debug(1, "Association failed: %s", err or "Unknown error")

    local e = tostring(err or "")
    local early_close =
         e:find("Couldn't read ASSOCIATE response:", 1, true)
      or e:lower():find("could not read pdu", 1, true)
      or e:lower():find("failed to receive pdu", 1, true)
      or e:lower():find("connection reset by peer", 1, true)

    if early_close then
      -- Treat as discovered even if the peer closed after our probe
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
      output.dicom  = "DICOM Service Provider discovered!"
      output.config = "Association ended early by peer"
    elseif e == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
      output.dicom  = "DICOM Service Provider discovered!"
      output.config = "Called AET check enabled (Rejected ANY-SCP)"
    end

    stdnse.debug(1, "Final output table contents (on failure):\n%s", stdnse.format_output(true, output))
    if output.dicom then return output else return nil end
  end

  -- Association was successful
  output.dicom = "DICOM Service Provider discovered!"
  if not called_aet_arg or called_aet_arg == "ANY-SCP" then
    output.config = "Any AET is accepted (Insecure)"
  end

  -- Prefer vendor/version when present
  if vendor then
    output.vendor = vendor
  end
  if version then
    local clean_version = dicom.extract_clean_version and dicom.extract_clean_version(version, vendor) or version
    output.version = clean_version or version
  end

  -- Fallbacks: if vendor missing -> show UID root; if version missing -> show raw UID
  if (not vendor) and uid then
    local root = dicom.extract_uid_root and dicom.extract_uid_root(uid) or uid
    output.uid_root = root
  end
  if (not version) and uid then
    output.impl_uid = uid
  end

  -- Populate Nmap version fields
  port.version.name = "dicom"
  if output.vendor then port.version.product = output.vendor end
  if output.version then port.version.version = output.version end
  nmap.set_port_version(host, port)

  stdnse.debug(1, "Final output table contents (on success):\n%s", stdnse.format_output(true, output))
  return output
end
