-- dicom-web-info.nse
--[[
Detects DICOM-related HTTP endpoints:
 - Orthanc REST API (/system) and extracts version if readable
 - OHIF Viewer (static front-end)
 - dcm4chee-arc UI2 (admin console) with strict fingerprinting

Usage:
  nmap -p 8042,3000,8080 --script dicom-web-info <target>
  nmap --script dicom-web-info --script-args dicom-web.ports=8042,3000,8080,dicom-web.orthanc.user=orthanc,dicom-web.orthanc.pass=orthanc <target>

Script classes: discovery, safe, version
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

local function lc(v) return (v or ""):lower() end
local function has(h, k)
  if not h then return nil end
  return h[k] or h[string.lower(k)]
end
local function body_has(b, needle)
  return b and string.find(string.lower(b), string.lower(needle), 1, true) ~= nil
end

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  return shortport.port_or_service({80,443,8042,3000,8080}, {"http","https"}, "tcp")(host, port)
end

action = function(host, port)
  local out = stdnse.output_table()
  local use_ssl = shortport.ssl(host, port)

  -- ---------- Orthanc ----------
  do
    local user = stdnse.get_script_args("dicom-web.orthanc.user")
    local pass = stdnse.get_script_args("dicom-web.orthanc.pass")
    local hdr  = { ["Accept"]="application/json" }
    if user and pass then
      hdr["Authorization"] = "Basic " .. base64.encode(user .. ":" .. pass)
    end
    local ok, resp = pcall(http.get, host, port, "/system", {timeout=5000, ssl=use_ssl, header=hdr})
    if ok and resp and resp.status then
      if resp.status == 200 and resp.body then
        local ver = resp.body:match('"[ ]*Version[ ]*"[ ]*:[ ]*"([^"]+)"')
        if ver then
          table.insert(out, ("Orthanc REST API: /system (version %s)"):format(ver))
        else
          table.insert(out, "Orthanc REST API: /system (reachable)")
        end
      elseif resp.status == 401 or resp.status == 403 then
        table.insert(out, "Orthanc REST API: /system (authentication required)")
      end
    end
  end

  -- ---------- dcm4chee-arc UI2 (be strict to avoid OHIF false positives) ----------
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, p in ipairs(paths) do
      local ok, resp = pcall(http.get, host, port, p, {timeout=5000, ssl=use_ssl})
      if ok and resp and resp.status and resp.body then
        local server = lc(has(resp.header, "Server") or "")
        local loc    = lc(has(resp.header, "Location") or "")
        local bdy    = lc(resp.body)
        local looks_like_arc =
           bdy:find("dcm4chee%-arc", 1, true) or
           bdy:find("dcm4che", 1, true) or
           server:find("wildfly", 1, true) or
           server:find("undertow", 1, true) or
           loc:find("/auth", 1, true)  -- keycloak redirect sometimes
        if looks_like_arc then
          if resp.status == 200 then
            table.insert(out, "DCM4CHEE Archive UI: /dcm4chee-arc/ui2/")
          else
            table.insert(out, "DCM4CHEE Archive UI: /dcm4chee-arc/ui2/ (authentication required)")
          end
          break
        end
      end
    end
  end

  -- ---------- OHIF ----------
  do
    local ok, resp = pcall(http.get, host, port, "/", {timeout=5000, ssl=use_ssl})
    if ok and resp and resp.status == 200 and resp.body then
      if body_has(resp.body, "OHIF") or body_has(resp.body, "app-config.js") then
        table.insert(out, "OHIF Viewer: detected at /")
      end
    end
  end

  if #out == 0 then return nil end
  return out
end
