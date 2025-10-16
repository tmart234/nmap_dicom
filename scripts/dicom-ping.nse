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
local dicom     = require "dicom"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"

-- Parse a comma/space separated port list into a lookup set.
local function parse_ports_arg(ports_str)
  if not ports_str then return nil end
  local set = {}
  for num in string.gmatch(ports_str, "%d+") do
    local n = tonumber(num)
    if n then set[n] = true end
  end
  return (next(set) and set) or nil
end

-- Default/common DICOM ports:
-- 104   = historical default
-- 11112 = commonly used for DICOM over TCP
-- 2761  = DICOM Upper Layer over TLS
-- 2762  = DICOM over TLS (service)
-- 4242  = Orthanc default (widely used in practice)
local COMMON_DICOM_PORTS = {104, 11112, 2761, 2762, 4242}

portrule = function(host, port)
  -- TCP and open, as usual for NSE protocol probes.
  if not (port.protocol == "tcp" and port.state == "open") then
    return false
  end

  -- Explicit override via --script-args
  local arg_str = stdnse.get_script_args("dicom-ping.ports")
  if arg_str then
    local want = parse_ports_arg(arg_str)
    if want and want[port.number] then
      stdnse.debug(1, "dicom-ping: matched script-arg port %d", port.number)
      return true
    end
  end

  -- Otherwise, run for common DICOM ports or if service is already identified as "dicom"
  if shortport.port_or_service(COMMON_DICOM_PORTS, "dicom", "tcp")(host, port) then
    stdnse.debug(1, "dicom-ping: matched common DICOM port/service (%d)", port.number)
    return true
  end

  return false
end

action = function(host, port)
  stdnse.debug(1, "dicom-ping: ACTION for %s:%d", host.ip, port.number)
  local out = stdnse.output_table()

  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  -- dicom.associate(host, port, calling_aet, called_aet)
  -- returns: status, err, version, vendor, uid
  local ok, err, version, vendor, uid = dicom.associate(host, port, nil, called_aet)

  if not ok then
    stdnse.debug(1, "Association failed: %s", tostring(err or "Unknown error"))

    -- Treat specific transport/early-close errors as discovery:
    -- some implementations/proxies reset when no DIMSE follows AC.
    local e = tostring(err or "")
    local early_close =
         e:find("Couldn't read ASSOCIATE response:", 1, true)
      or e:lower():find("could not read pdu", 1, true)
      or e:lower():find("failed to receive pdu", 1, true)
      or e:lower():find("connection reset by peer", 1, true)

    if early_close then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
      out.dicom  = "DICOM Service Provider discovered!"
      out.config = "Association ended early by peer"
      return out
    end

    if e == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
      out.dicom  = "DICOM Service Provider discovered!"
      if not called_aet or called_aet == "ANY-SCP" then
        out.config = "Called AET check enabled (Rejected ANY-SCP)"
      else
        out.config = string.format("Association Rejected (Tried AET: %s)", called_aet)
      end
      return out
    end

    -- Unknown failure: stay silent to avoid false positives.
    return nil
  end

  -- Success path: association accepted.
  out.dicom = "DICOM Service Provider discovered!"
  if not called_aet or called_aet == "ANY-SCP" then
    out.config = "Any AET is accepted (Insecure)"
  end

  -- Identity (prefer vendor/version; fall back to implementation UID).
  if vendor then
    out.vendor = vendor
  end
  if version then
    local clean = (dicom.extract_clean_version and dicom.extract_clean_version(version, vendor)) or version
    out.version = clean or version
  end
  if uid then
    -- Help users even when vendor/version are missing
    if not out.vendor then
      local root = (dicom.extract_uid_root and dicom.extract_uid_root(uid)) or uid
      out.uid_root = root
    end
    if not out.version then
      out.impl_uid = uid
    end
  end

  -- Populate Nmap’s service fingerprint fields.
  port.version.name = "dicom"
  if out.vendor  then port.version.product = out.vendor end
  if out.version then port.version.version = out.version end
  nmap.set_port_version(host, port)

  return out
end