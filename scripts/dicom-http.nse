-- scripts/dicom-http.nse
--[[
Detects DICOM-related HTTP surfaces:
  * Orthanc REST: fetches /system and reports version (supports Basic Auth)
  * OHIF Viewer: detects via landing page markers

@usage
nmap -p8042 --script dicom-http <target>
nmap -p8042 --script dicom-http --script-args dicom-http.user=orthanc,dicom-http.pass=orthanc <target>
nmap -p80,443,3000 --script dicom-http <target>
nmap --script dicom-http --script-args dicom-http.ports=8042,3000 <target>

@output
PORT     STATE SERVICE
8042/tcp open  http
| dicom-http:
|   orthanc: REST reachable
|_  version: 1.12.0

PORT     STATE SERVICE
3000/tcp open  http
| dicom-http:
|_  ohif_viewer: detected
]]

author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe","version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local base64    = require "base64"
local string    = require "string"

local function parse_ports_arg(s)
  if not s then return nil end
  local t = {}
  for p in string.gmatch(s, "%d+") do t[tonumber(p)] = true end
  return next(t) and t or nil
end

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  -- Optional explicit list override
  local arg = stdnse.get_script_args("dicom-http.ports")
  local set = parse_ports_arg(arg)
  if set and set[port.number] then return true end
  -- Otherwise: only HTTP(S) services/ports
  return shortport.port_or_service({80, 443, 8042, 3000}, {"http","https"}, "tcp")(host, port)
end

local function is_https(port)
  local name = (port.service or port.version and port.version.name) or ""
  name = type(name) == "string" and name:lower() or ""
  return name == "https" or port.tls == true or port.number == 443
end

local function get(host, port, path, user, pass)
  local opts = {
    timeout = 5000,
    header = { ["Accept"] = "application/json, */*;q=0.1" },
    ssl = is_https(port)
  }
  if user and pass then
    opts.header["Authorization"] = "Basic " .. base64.encode(user .. ":" .. pass)
  end
  local ok, resp = pcall(http.get, host, port, path, opts)
  if not ok then return nil end
  return resp
end

action = function(host, port)
  local out = stdnse.output_table()

  local user = stdnse.get_script_args("dicom-http.user")
  local pass = stdnse.get_script_args("dicom-http.pass")

  -- 1) Try Orthanc REST /system
  do
    local resp = get(host, port, "/system", user, pass)
    if resp and resp.status == 200 and resp.body then
      local ct = (resp.header and resp.header["content-type"] or ""):lower()
      if ct:find("json", 1, true) or resp.body:find('"%s*Version%s*"%s*:%s*"', 1) then
        local ver = resp.body:match('"%s*Version%s*"%s*:%s*"([^"]+)"')
                   or resp.body:match('"OrthancVersion"%s*:%s*"([^"]+)"')
        out["orthanc"] = "REST reachable"
        if ver then out["version"] = ver end
        return out
      end
    end
    -- If 401/403 and no creds were supplied, just don’t report; another script-arg run can supply creds.
  end

  -- 2) Try OHIF Viewer (HTML landing page)
  do
    local resp = get(host, port, "/", nil, nil)
    if resp and resp.status and resp.status >= 200 and resp.status < 400 and resp.body then
      local body = resp.body
      -- Common markers: title, window.config, logos, meta
      if body:find("OHIF", 1, true)
         or body:match("<title>[^<]*OHIF[^<]*</title>")
         or body:lower():find("ohif%-viewer", 1, true)
         or body:lower():find("ohif/app", 1, true) then
        out["ohif_viewer"] = "detected"
        return out
      end
    end
  end

  return nil
end
