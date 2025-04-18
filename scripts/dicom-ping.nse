description = [[
Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.
 It also detects if the server allows any called Application Entity Title or not.

The script responds with the message "Called AET check enabled" when the association request
 is rejected due configuration. This value can be bruteforced.

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

author = "Paulino Calderon <calderon()calderonpale.com>, Tyler M <tmart23()gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe", "auth"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"
local http = require "http"

portrule = shortport.port_or_service({104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp", "open")

action = function(host, port)
  local output = stdnse.output_table()

  -- Try association
  -- Get status, error message OR nil, version string, vendor string
  local dcm_status, err_or_nil, version, vendor = dicom.associate(host, port)

  -- Handle association rejection or pcall errors from associate
  if dcm_status == false then
    stdnse.debug1("Association failed: %s", err_or_nil or "Unknown error")
    -- Check specifically for the REJECT error string set inside associate
    if err_or_nil == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)

      output.dicom = "DICOM Service Provider discovered!"
      output.config = "Called AET check enabled"
      output.auth = "Cannot test User Identity Negotiation (AET required)"
    end
    -- Also print final table on failure for debugging
    stdnse.debug1("Final output table contents (on failure):\n%s", stdnse.format_output(true, output))
    return output
  end

  -- If status is true, err_or_nil should be nil (as returned by associate on success)
  -- version and vendor might be nil if parsing failed internally

  -- Debug output for troubleshooting
  stdnse.debug1("Associate success - Raw Version: %s, Raw Vendor: %s",
                version or "nil",
                vendor or "nil")

  -- Association successful, report basic discovery
  port.version.name = "dicom" -- Base service name
  nmap.set_port_version(host, port)

  output.dicom = "DICOM Service Provider discovered!"
  output.config = "Any AET is accepted (Insecure)"

  local final_version = nil
  local final_vendor = nil

  -- Process version information if available from associate
  if version then
    stdnse.debug1("Raw version string from associate: %s", version)
    -- Try cleaning the version string (e.g., OFFIS_DCMTK_369 -> 3.6.9)
    -- Pass vendor hint, as clean_version might need it
    local clean_version = dicom.extract_clean_version(version, vendor)
    if clean_version then
      stdnse.debug1("Cleaned version: %s", clean_version)
      final_version = clean_version
    else
      stdnse.debug1("Could not clean version string, using raw: %s", version)
      final_version = version -- Fallback to raw version string
    end
    output.version = final_version -- Add to output table
  else
     stdnse.debug1("No version string returned from associate.")
  end

  -- Process vendor information if available from associate
  if vendor then
    stdnse.debug1("Vendor from associate: %s", vendor)
    final_vendor = vendor
    output.vendor = final_vendor -- Add to output table

    -- Orthanc-specific REST check (only if vendor identified as Orthanc)
    -- NOTE: In this case, vendor was DCMTK, so this block won't run,
    -- but keeping it for generality.
    if final_vendor == "Orthanc" then
      stdnse.debug1("Vendor identified as Orthanc, trying REST API for version...")

      local ports_to_try = {8042, port.number} -- Try default 8042 first
      local orthanc_version_found = false

      for _, test_port in ipairs(ports_to_try) do
        stdnse.debug1("Trying Orthanc REST API on port %d", test_port)
        local status, response = pcall(http.get, host, test_port, "/system", {timeout=3000}) -- Use pcall for safety

        if status and response and response.status then
          stdnse.debug1("HTTP response status: %d from port %d", response.status, test_port)
          if response.status == 200 and response.body then
            stdnse.debug1("Response body length: %d", #(response.body))
            local rest_ver = response.body:match('"Version"%s*:%s*"([%d.]+)"')
            if rest_ver then
              stdnse.debug1("Found Orthanc version via REST: %s", rest_ver)
              output.version = rest_ver -- Overwrite version if found via REST
              output.vendor = "Orthanc"  -- Ensure vendor is Orthanc
              output.notes = "Version confirmed via REST API"
              final_version = rest_ver -- Update final_version as well
              orthanc_version_found = true

              -- Update Nmap's service detection info
              port.version.product = "Orthanc"
              port.version.version = rest_ver
              nmap.set_port_version(host, port)
              break -- Stop trying ports if version found
            else
              stdnse.debug1("Version field not found in JSON response from port %d", test_port)
            end
          end
        else
          -- Log error from pcall if http.get failed
          stdnse.debug1("Failed to connect/get from REST API on port %d: %s", test_port, (response and tostring(response)) or "pcall failed")
        end
      end -- end for loop

      if not orthanc_version_found then
        stdnse.debug1("Could not determine Orthanc version via REST API")
        -- Still set product in Nmap's version detection if vendor was Orthanc
        port.version.product = "Orthanc"
        nmap.set_port_version(host, port)
      end
    else
       -- If vendor wasn't Orthanc, still try setting product if vendor known
       -- Use final_vendor and final_version captured earlier
       if final_vendor then
          port.version.product = final_vendor
          if final_version then port.version.version = final_version end
          nmap.set_port_version(host, port)
       end
    end -- end Orthanc check
  else
     stdnse.debug1("No vendor returned from associate.")
  end -- end vendor check

  -- Final debug output before returning
  stdnse.debug1("Final output table contents:\n%s", stdnse.format_output(true, output))

  return output
end -- <<<--- THIS IS THE MISSING 'end' THAT WAS ADDED BACK