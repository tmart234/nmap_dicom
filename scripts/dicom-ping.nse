--[[
Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.
It also detects if the server allows any called Application Entity Title or not.

The script responds with the message "Called AET check enabled" when the association request
is rejected due configuration. This value can be bruteforced using dicom-brute.

The Implementation Class UID identifies the implementation (often enough to infer
the toolkit or vendor), and the Implementation Version Name can often be used to
extract a meaningful version string.

C-ECHO requests are commonly known as DICOM ping as they are used to test connectivity.
Normally, a 'DICOM ping' is formed as follows:
* Client -> A-ASSOCIATE request -> Server
* Server -> A-ASSOCIATE ACCEPT/REJECT -> Client
* Client -> C-ECHO request -> Server
* Server -> C-ECHO response -> Client
* Client -> A-RELEASE request -> Server
* Server -> A-RELEASE response -> Client

For this script we only send the A-ASSOCIATE request and look for the success code
(or an explicit A-ASSOCIATE-REJECT) in the response as it seems to be a reliable
way of detecting DICOM servers.

On the IANA DICOM/TLS port (2762), if a plaintext A-ASSOCIATE fails with a characteristic
"Short PDU header" error, this script reports a *possible* DICOM/TLS endpoint while
intentionally omitting vendor/version information.
]]

---
-- @usage nmap -p4242 --script dicom-ping <target>
-- @usage nmap -sV --script dicom-ping <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.ports=11114,11115 <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.extended <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.extended,dicom-ping.oids <target>
--
-- @args dicom.called_aet       Called Application Entity Title. Default: ANY-SCP
-- @args dicom-ping.ports       Optional comma-separated list of ports to probe
--                              (e.g. "104,11112,2761,2762,4242"). By default,
--                              the script runs on common DICOM ports or when
--                              the service is already identified as "dicom".
-- @args dicom-ping.extended    If set, prints additional identification fields
--                              (implementation class UID and implementation
--                              version name) from the A-ASSOCIATE-AC.
-- @args dicom-ping.oids        If set together with dicom-ping.extended and a
--                              known vendor/version, also prints impl_class_uid
--                              even when vendor/version are already present.
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
-- Example TLS endpoint (heuristic):
-- 2762/tcp open  dicom-tls syn-ack
-- | dicom-ping:
-- |   dicom: Possible DICOM/TLS endpoint (plaintext A-ASSOCIATE not accepted)
-- |_  tls_hint: Port 2762 is open, but DICOM associate could not be completed. This port often expects a TLS client handshake.
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
local dicom     = require "dicom"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"
local tonumber  = tonumber

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
      stdnse.debug1("dicom-ping: matched script-arg port %d", port.number)
      return true
    end
  end

  -- Otherwise, run for common DICOM ports or if service is already identified as "dicom"
  if shortport.port_or_service(COMMON_DICOM_PORTS, "dicom", "tcp")(host, port) then
    stdnse.debug1("dicom-ping: matched common DICOM port/service (%d)", port.number)
    return true
  end

  return false
end

action = function(host, port)
  stdnse.debug1("dicom-ping: ACTION for %s:%d", host.ip, port.number)
  local out = stdnse.output_table()

  local called_aet  = stdnse.get_script_args("dicom.called_aet")
  local extended    = stdnse.get_script_args("dicom-ping.extended") ~= nil
  local show_oids   = stdnse.get_script_args("dicom-ping.oids")     ~= nil

  -- dicom.associate(host, port, calling_aet, called_aet)
  -- returns: status, err, version, vendor, uid, impl_version_name (last may be nil)
  local ok, err, version, vendor, uid, impl_version_name =
    dicom.associate(host, port, nil, called_aet)

  if not ok then
    stdnse.debug1("Association failed: %s", tostring(err or "Unknown error"))

    local e = tostring(err or "")

    -- Only treat a clearly signalled ASSOCIATE-REJECT as positive DICOM detection.
    if e == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)

      out.dicom  = "DICOM Service Provider discovered!"
      if not called_aet or called_aet == "ANY-SCP" then
        out.config = "Called AET check enabled"
      else
        out.config = string.format("Association Rejected (Tried AET: %s)", called_aet)
      end
      return out
    end

    -- Heuristic for the IANA DICOM/TLS port (2762):
    if tonumber(port.number) == 2762 and e:lower():match("short pdu header") then
      out.dicom    = "Possible DICOM/TLS endpoint (plaintext A-ASSOCIATE not accepted)"
      out.tls_hint = "Port 2762 is open, but DICOM associate could not be completed. This port often expects a TLS client handshake."
      out.error    = e
      -- Intentionally do NOT set port.version.product/version in this heuristic path.
      return out
    end

    -- Unknown failure or timeout: stay silent to avoid false positives.
    return nil
  end

  -- Success path: association accepted.
  out.dicom = "DICOM Service Provider discovered!"

  if not called_aet or called_aet == "ANY-SCP" then
    out.config = "Any AET is accepted (Insecure)"
  else
    out.config = string.format("Called AET enforced (used: %s)", called_aet)
  end

  -- Optional hint if scanning the IANA DICOM/TLS port.
  if tonumber(port.number) == 2762 then
    out.tls_hint = "Likely TLS-required endpoint (no plaintext DICOM on this port)"
  end

  if vendor then
    out.vendor = vendor
    port.version.product = vendor
  end
  if version then
    out.version = version
    port.version.version = version
  end
  port.version.name = "dicom"
  nmap.set_port_version(host, port)

  if extended then
    if uid then
      local label = uid
      if dicom.extract_uid_root then
        local root = dicom.extract_uid_root(uid)
        if root and root ~= uid then
          label = string.format("%s (root: %s)", uid, root)
        end
      end

      if vendor or version then
        -- We already have human-ish identity; only show UID if explicitly requested.
        if show_oids then
          out.impl_class_uid = label
        end
      else
        -- No vendor/version, but we do have a UID: this is where it's genuinely useful.
        out.impl_class_uid = label
        out.note = "Look up impl_class_uid in a DICOM OID registry for implementation details"
      end
    end

    if impl_version_name then
      -- Raw Implementation Version Name from User Info (0x55), e.g. PYNETDICOM_304, OFFIS_DCMTK_369.
      out.impl_version_name = impl_version_name
    end
  end

  return out
end
