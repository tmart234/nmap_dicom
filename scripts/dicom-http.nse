-- scripts/dicom-http.nse
--[[
Detect Orthanc REST (report version) and/or OHIF Viewer over HTTP(S).

@usage
nmap -p8042 --script dicom-http --script-args dicom-http.user=orthanc,dicom-http.pass=orthanc <target>
nmap -p3000 --script dicom-http <target>

@output
PORT     STATE SERVICE
8042/tcp open  http
| dicom-http:
|   orthanc_rest: reachable
|_  version: 1.12.9

PORT     STATE SERVICE
3000/tcp open  http
|_dicom-http: ohif_viewer: detected
]]

author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe","version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"

-- base64 is optional; load safely
local base64_ok, base64 = pcall(require, "base64")

local function parse_ports_arg(s)
  if not s then return nil end
  local t = {}
  for p in string.gmatch(s, "%d+") do t[tonumber(p)] = true end
  return next(t) and t or nil
end

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  -- allow explicit override
  local set = parse_ports_arg(stdnse.get_script_args("dicom-http.ports"))
  if set and set[port.number] then return true end
  -- default interesting ports
  return shortport.port_or_service({80, 443, 8042, 3000}, {"http","https"}, "tcp")(host, port)
end

local function try_http(host, port, path, opts)
  local ok, resp = pcall(http.get, host, port, path, opts)
  if not ok or not resp then return nil end
  return resp
end

local function build_opts(user, pass)
  local opts = { timeout = 5000, header = { ["Accept"] = "application/json, text/html" } }
  if user and pass and base64_ok and base64 then
    local enc = base64.encode or base64.enc
    if enc then
      opts.header["Authorization"] = "Basic " .. enc(user .. ":" .. pass)
    end
  end
  return opts
end

action = function(host, port)
  local out = stdnse.output_table()

  local user = stdnse.get_script_args("dicom-http.user")
  local pass = stdnse.get_script_args("dicom-http.pass")
  local opts = build_opts(user, pass)

  -- 1) Try Orthanc REST /system
  do
    local resp = try_http(host, port, "/system", opts)
    if resp and resp.status == 200 and resp.body then
      -- parse "Version": "x.y.z"
      local ver = resp.body:match('"%s*[Vv]ersion%s*"%s*:%s*"([^"]+)"')
      out.orthanc_rest = "reachable"
      if ver then out.version = ver end
      return out
    end
    -- If 401 without creds, don’t error—just fall through to OHIF check
  end

  -- 2) Try OHIF Viewer detection (HTML root)
  do
    local resp = try_http(host, port, "/", { timeout = 5000 })
    if resp and resp.status and resp.body then
      local body = resp.body
      if body:find("OHIF%W*Viewer") or body:find("window%.config") or body:find("ohif") then
        return { ["ohif_viewer"] = "detected" }
      end
    end
  end

  -- Nothing to report
  return nil
end
