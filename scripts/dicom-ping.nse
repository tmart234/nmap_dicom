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
categories = {"discovery", "default", "safe", "auth"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"
local http = require "http"
local string = require "string"
local table = require "table"

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
  -- Common ports: 104, 2761, 2762, 4242, 11112. Added 2345 from dicom-brute's rule.
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

  -- Try association using defaults (ECHOSCU -> ANY-SCP) or script args if provided
  stdnse.debug(1, "dicom-ping: Calling dicom.associate for %s:%d...", host.ip, port.number)
  local dcm_status, err, version, vendor = dicom.associate(host, port) -- No explicit AETs passed here

  -- Handle association rejection
  if dcm_status == false then
    stdnse.debug1("Association failed: %s", err or "Unknown error")
    -- Check if the failure was specifically due to AET rejection
    if err == "ASSOCIATE REJECT received" then
      -- Set service name to dicom even on failure if reject is received
      port.version.name = "dicom"
      nmap.set_port_version(host, port)

      output.dicom = "DICOM Service Provider discovered!"
      output.config = "Called AET check enabled" -- Indicate AET is required
    end
    stdnse.debug1("Final output table contents (on failure):\n%s", stdnse.format_output(true, output))
    return output -- Return output table even on failure
  end

  -- Association was successful
  stdnse.debug1("Associate success - Version: %s, Vendor: %s",
                version or "nil",
                vendor or "nil")

  -- Set port info as DICOM
  port.version.name = "dicom"
  nmap.set_port_version(host, port) -- Update port info in Nmap

  output.dicom = "DICOM Service Provider discovered!"
  if not called_aet_arg or called_aet_arg == "ANY-SCP" then
    output.config = "Any AET is accepted (Insecure)"
  else
      stdnse.debug1("Specific Called AET ('%s') used successfully.", called_aet_arg)
  end
  -- Add version information if available
  if version then
    stdnse.debug1("Detected DICOM version string: %s", version)
    -- Try cleaning the version string using the library function
    local clean_version = dicom.extract_clean_version(version, vendor)
    output.version = clean_version or version -- Use cleaned version if successful, else original
    stdnse.debug1("Reported version: %s", output.version)
  end

  -- Add vendor information if available
  if vendor then
    stdnse.debug1("Detected DICOM vendor: %s", vendor)
    output.vendor = vendor

    -- Orthanc-specific REST check for version confirmation/refinement
    if vendor == "Orthanc" then
      stdnse.debug1("Detected Orthanc, trying REST API for version...")

      -- Ports to try for Orthanc REST API (common default and the DICOM port itself)
      local ports_to_try = {8042, port.number}
      local orthanc_version_found = false

      for _, test_port in ipairs(ports_to_try) do
        stdnse.debug1("Trying Orthanc REST API on port %d", test_port)
        -- Use pcall for safety when making HTTP request
        local status, response = pcall(http.get, host, test_port, "/system", {timeout=3000})

        if status and response and response.status then -- Check pcall status first
          stdnse.debug1("HTTP response status: %d from port %d", response.status, test_port)

          if response.status == 200 and response.body then
            stdnse.debug1("Response body length: %d", #(response.body))
            -- Attempt to parse version from JSON response
            local ver = response.body:match('"Version"%s*:%s*"([%d.]+)"')
            if ver then
              stdnse.debug1("Found Orthanc version via REST: %s", ver)
              -- Update output and Nmap port info with more specific info
              output.version = ver
              output.vendor = "Orthanc"
              output.notes = "Version confirmed via REST API"
              orthanc_version_found = true

              port.version.product = "Orthanc"
              port.version.version = ver
              nmap.set_port_version(host, port)
              break -- Stop checking ports once version found
            else
              stdnse.debug1("Version field not found in JSON response from port %d", test_port)
            end
          end
        else
          stdnse.debug1("Failed to connect/get from REST API on port %d: %s", test_port, (response and tostring(response)) or "pcall failed")
        end
      end -- end for loop checking REST ports

      if not orthanc_version_found then
        stdnse.debug1("Could not determine Orthanc version via REST API")
        -- Still report vendor as Orthanc based on initial DICOM association
        output.vendor = "Orthanc"
        port.version.product = "Orthanc"
        -- Don't overwrite version if already found via DICOM
        nmap.set_port_version(host, port)
      end
    end -- end Orthanc check
  end -- end vendor check

  stdnse.debug1("Final output table contents (on success):\n%s", stdnse.format_output(true, output))

  return output
end