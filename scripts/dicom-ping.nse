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

-- Extract version from version string based on vendor
local function extract_clean_version(version_str, vendor)
  if not version_str then return nil end
  
  -- DCMTK versions
  if vendor == "DCMTK" then
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
  end
  
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
  
  -- FujiFilm Synapse versions
  if vendor == "FujiFilm" then
    -- Format: Synapse_5.7.110
    local ver = version_str:match("Synapse_(%d+%.%d+%.%d+)")
    if ver then
      return ver
    end
  end
  
  -- Agfa IMPAX versions
  if vendor == "Agfa" then
    -- Format: IMPAX_6.5.1.1234
    local ver = version_str:match("IMPAX_(%d+%.%d+%.%d+%.%d+)")
    if ver then
      return ver
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

action = function(host, port)
  local output = stdnse.output_table()
  
  -- Try association
  local dcm_status, err, version, vendor = dicom.associate(host, port)
  
  -- Handle association rejection
  if dcm_status == false then
    stdnse.debug1("Association failed: %s", err or "Unknown error")
    if err == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
  
      output.dicom = "DICOM Service Provider discovered!"
      output.config = "Called AET check enabled"
    end
    return output
  end
  
  -- Debug output for troubleshooting
  stdnse.debug1("Associate success - Version: %s, Vendor: %s", 
                version or "nil", 
                vendor or "nil")
  
  -- Association successful
  port.version.name = "dicom"
  nmap.set_port_version(host, port)

  output.dicom = "DICOM Service Provider discovered!"
  output.config = "Any AET is accepted (Insecure)"

  -- Add version information if available
  if version then
    stdnse.debug1("Detected DICOM version string: %s", version)
    local clean_version = extract_clean_version(version, vendor)
    if clean_version then
      stdnse.debug1("Cleaned version: %s", clean_version)
      output.version = clean_version
    else
      output.version = version
    end
  end

  -- Add vendor information if available
  if vendor then
    stdnse.debug1("Detected DICOM vendor: %s", vendor)
    output.vendor = vendor
    
    -- Orthanc-specific REST check
    if vendor == "Orthanc" then
      stdnse.debug1("Detected Orthanc, trying REST API for version...")
      
      -- Try default Orthanc port first (8042)
      local ports_to_try = {8042, port.number}
      local orthanc_version_found = false
      
      for _, test_port in ipairs(ports_to_try) do
        stdnse.debug1("Trying Orthanc REST API on port %d", test_port)
        local response = http.get(host, test_port, "/system", {timeout=3000})
        if response and response.status then
          stdnse.debug1("HTTP response status: %d from port %d", response.status, test_port)
          
          if response.status == 200 then
            stdnse.debug1("Response body length: %d", #(response.body or ""))
            
            if response.body then
              -- Look for Version field in JSON response
              local ver = response.body:match('"Version"%s*:%s*"([%d.]+)"')
              if ver then
                stdnse.debug1("Found Orthanc version via REST: %s", ver)
                output.version = ver
                output.vendor = "Orthanc"
                output.notes = "Version confirmed via REST API"
                orthanc_version_found = true
                
                -- Update Nmap's version information
                port.version.product = "Orthanc"
                port.version.version = ver
                nmap.set_port_version(host, port)
                break
              else
                stdnse.debug1("Version field not found in JSON response")
              end
            end
          end
        else
          stdnse.debug1("Failed to connect to REST API on port %d", test_port)
        end
      end
      
      if not orthanc_version_found then
        stdnse.debug1("Could not determine Orthanc version via REST API")
        -- Still set vendor information
        output.vendor = "Orthanc"
        port.version.product = "Orthanc"
        nmap.set_port_version(host, port)
      end
    end
  end

  return output
end