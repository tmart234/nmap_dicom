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
]]

---
-- @usage nmap -p4242 --script dicom-ping <target>
-- @usage nmap -sV --script dicom-ping <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.ports=11114,11115 <target>
-- @usage nmap -v --script dicom-ping <target>
-- @usage nmap --script dicom-ping --script-args dicom-ping.extended <target>
--
-- @args dicom.called_aet       Called Application Entity Title. Default: ANY-SCP
-- @args dicom-ping.ports       Optional comma-separated list of ports to probe
--                              (e.g. "104,11112,2761,2762,4242"). By default,
--                              the script runs on common DICOM ports or when
--                              the service is already identified as "dicom".
-- @args dicom-ping.extended    If set, prints additional identification fields
--                              (implementation class UID and implementation
--                              version name) from the A-ASSOCIATE-AC. This behaves
--                              identically to running Nmap with verbosity (-v).
--
-- @output
-- PORT     STATE SERVICE REASON
-- 4242/tcp open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |_  config: Called AET check enabled
--
-- Known toolkit identified (e.g. Orthanc running natively):
-- PORT     STATE SERVICE REASON
-- 4242/tcp open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   vendor: Orthanc
-- |_  version: 1.11.0
--
-- Toolkit/manufacturer mismatch (verbose or extended):
-- PORT     STATE SERVICE REASON
-- 104/tcp  open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   vendor: DCMTK
-- |   version: 3.6.4
-- |   device_vendor: Philips
-- |_  impl_class_uid: 1.3.46.670589.54.2.20.6
--
-- Manufacturer OID recognized but no toolkit identified:
-- PORT     STATE SERVICE REASON
-- 104/tcp  open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   device_vendor: GE Healthcare
-- |   impl_class_uid: 1.2.840.113619.6.5
-- |   impl_version_name: GE_PACS_V4
-- |_  version: 4
--
-- Completely unrecognized implementation (default output):
-- PORT     STATE SERVICE REASON
-- 104/tcp  open  dicom   syn-ack
-- | dicom-ping:
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   impl_class_uid: 1.2.3.4.5.6.7.8.9
-- |   impl_uid_root: 1.2.3.4.5.6.7.8
-- |   impl_version_name: UNKNOWN_STACK_V2
-- |_  note: Unrecognized implementation - look up impl_class_uid in a DICOM OID registry
--
-- @xmloutput
-- <script id="dicom-ping" output="&#xa;  dicom: DICOM Service Provider discovered!&#xa;
--   config: Called AET check enabled"><elem key="dicom">DICOM Service Provider discovered!</elem>
-- <elem key="config">Called AET check enabled</elem>
-- </script>
--
-- @xmloutput
-- <script id="dicom-ping" output="&#xa;  dicom: DICOM Service Provider discovered!&#xa;  config: Any AET is accepted (Insecure)&#xa;  vendor: Orthanc&#xa;  version: 1.11.0"><elem key="dicom">DICOM Service Provider discovered!</elem>
-- <elem key="config">Any AET is accepted (Insecure)</elem>
-- <elem key="vendor">Orthanc</elem>
-- <elem key="version">1.11.0</elem>
-- </script>
---

author = "Paulino Calderon <calderon()calderonpale.com>, Tyler M <tmart234()gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "version", "safe", "auth"}

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
local COMMON_DICOM_PORTS = {104, 11112, 2761, 2762, 4242}

-- Cache custom ports at script load so we don't parse it on every open port
local custom_ports_arg = stdnse.get_script_args("dicom-ping.ports")
local custom_ports_set = parse_ports_arg(custom_ports_arg)

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then
    return false
  end

  if custom_ports_set and custom_ports_set[port.number] then
    stdnse.debug1("dicom-ping: matched script-arg port %d", port.number)
    return true
  end

  -- Notice the "ssl" removal from the protocol array here compared to earlier attempts. 
  -- Nmap expects IP layer protocols ("tcp", "udp") in the third argument.
  if shortport.port_or_service(COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp")(host, port) then
    stdnse.debug1("dicom-ping: matched common DICOM port/service (%d)", port.number)
    return true
  end

  return false
end

action = function(host, port)
  stdnse.debug1("dicom-ping: ACTION for %s:%d", host.ip, port.number)
  local out = stdnse.output_table()

  local called_aet = stdnse.get_script_args("dicom.called_aet")
  local extended   = stdnse.get_script_args("dicom-ping.extended") ~= nil

  -- Safely check for TLS using Nmap's correct internal properties
  local is_tls = (port.version and port.version.service_tunnel == "ssl") or 
                 (port.version and type(port.version.name) == "string" and port.version.name:match("tls"))

  -- dicom.associate handles the heavy lifting, including native SSL wrapping
  -- Returns: ok, err, version, vendor, uid, impl_version_name, device_vendor, uid_category
  local ok, err, version, vendor, uid, impl_version_name, device_vendor, uid_category = dicom.associate(host, port, nil, called_aet)

  if not ok then
    stdnse.debug1("Association failed: %s", tostring(err or "Unknown error"))
    local e = tostring(err or "")

    -- Only treat a clearly signalled ASSOCIATE-REJECT as positive DICOM detection.
    if e == "ASSOCIATE REJECT received" then
      port.version.name = is_tls and "dicom-tls" or "dicom"
      nmap.set_port_version(host, port)

      out.dicom  = "DICOM Service Provider discovered!"
      if not called_aet or called_aet == "ANY-SCP" then
        out.config = "Called AET check enabled"
      else
        out.config = string.format("Association Rejected (Tried AET: %s)", called_aet)
      end
      return out
    end

    -- Catch mTLS rejections (when the connection fails at the TLS layer)
    if is_tls then
      out.dicom    = "TLS endpoint detected, but DICOM association failed."
      out.tls_hint = "Server likely requires Mutual TLS (mTLS) with valid client certificates."
      out.error    = e
      
      port.version.name = "dicom-tls"
      nmap.set_port_version(host, port)
      return out
    end

    -- Heuristic fallback if user didn't run -sV but hits IANA DICOM/TLS port.
    if not is_tls and tonumber(port.number) == 2762 and e:lower():match("short pdu header") then
      out.dicom    = "Possible DICOM/TLS endpoint (plaintext A-ASSOCIATE not accepted)"
      out.tls_hint = "Port 2762 is open, but DICOM associate could not be completed. Rerun with -sV or --script+ssl to confirm."
      out.error    = e
      return out
    end

    -- Unknown failure or timeout: stay silent to avoid false positives.
    return nil
  end

  -- =========================================================================
  -- Success path: association accepted.
  -- =========================================================================
  out.dicom = "DICOM Service Provider discovered!"
  if not called_aet or called_aet == "ANY-SCP" then
    out.config = "Any AET is accepted (Insecure)"
  else
    out.config = string.format("Called AET enforced (used: %s)", called_aet)
  end

  if is_tls then
    out.tls_status = "Successfully associated over TLS"
  elseif tonumber(port.number) == 2762 then
    out.tls_hint = "Warning: Plaintext DICOM detected on IANA TLS port"
  end

  -- vendor = toolkit/product actually running (from 0x55 first, 0x52 toolkit fallback)
  -- device_vendor = device manufacturer from 0x52 when category is "manufacturer"
  local is_verbose = nmap.verbosity() > 0 or extended
  local identified = (vendor ~= nil)

  if vendor then
    port.version.product = vendor
    out.vendor = vendor
  end

  if version then
    port.version.version = version
    out.version = version
  end

  -- device_vendor: always show when present — it's asset-relevant context
  if device_vendor then
    out.device_vendor = device_vendor
    port.version.extrainfo = "Device: " .. device_vendor
  end

  port.version.name = is_tls and "dicom-tls" or "dicom"
  nmap.set_port_version(host, port)

  ---------------------------------------------------------------------------
  -- Raw identification fields: impl_class_uid, impl_uid_root, impl_version_name
  --
  -- Nmap convention: when fingerprinting fails, surface raw data so the
  -- operator can do manual lookup (analogous to -sV showing an unmatched
  -- service fingerprint).
  --
  -- Show policy:
  --   identified + verbose     -> show uid (for verification)
  --   identified + mismatch    -> show uid (documents the discrepancy)
  --   NOT identified           -> ALWAYS show uid + root + raw version
  --                               (this is the most common case in clinical
  --                               environments; hiding it behind -v loses
  --                               the most important data)
  ---------------------------------------------------------------------------

  if uid then
    if not identified then
      -- Unrecognized implementation: promote everything to default output
      out.impl_class_uid = uid
      local uid_root = dicom.extract_uid_root(uid)
      if uid_root and uid_root ~= uid then
        out.impl_uid_root = uid_root
      end
    elseif is_verbose or device_vendor then
      -- Identified but verbose or mismatch: show UID for cross-reference
      out.impl_class_uid = uid
    end
  end

  if impl_version_name then
    if not identified then
      -- Unrecognized: always show raw version name for manual identification
      out.impl_version_name = impl_version_name
    elseif is_verbose and version ~= impl_version_name then
      -- Identified + verbose: show only if it differs from cleaned version
      out.impl_version_name = impl_version_name
    end
  end

  -- Note for operator when we couldn't identify anything
  if not identified and not device_vendor then
    out.note = "Unrecognized implementation - look up impl_class_uid in a DICOM OID registry"
  elseif not identified and device_vendor then
    out.note = "Device manufacturer identified but DICOM toolkit unknown - look up impl_class_uid for stack details"
  end

  return out
end
