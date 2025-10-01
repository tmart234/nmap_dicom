-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints:
--  - Orthanc REST API (/system) with version extraction
--  - OHIF Viewer
--  - dcm4chee-arc UI2 (admin console)
--
-- Usage:
--   nmap -p 8042,3000,8080 --script dicom-web-info <target>
--   nmap --script dicom-web-info \
--        --script-args dicom-web.ports=8042,3000,8080,dicom-web.orthanc.user=orthanc,dicom-web.orthanc.pass=orthanc \
--        <target>
--
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"

-- optional base64 (API differs across Nmap versions)
local base64_ok, base64 = pcall(require, "base64")

local function parse_ports_arg(s)
  if not s then return nil end
  local t = {}
  for p in string.gmatch(s, "%d+") do t[tonumber(p)] = true end
  return next(t) and t or nil
end

local function to_s(v)
  if v == nil then return "" end
  local t = type(v)
  if t == "string" then return v end
  if t == "table" then return table.concat(v, ",") end
  return tostring(v)
end

local function lc(v) return to_s(v):lower() end

local function hget(h, k)
  if not h then return nil end
  return h[k] or h[string.lower(k)] or h[string.upper(k)]
end

local function body_has(b, needle)
  return b and string.find(lc(b), lc(needle), 1, true) ~= nil
end

-- Build Authorization: Basic ... header safely across Nmap versions
local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  -- Prefer http.basic_auth if present
  if http.basic_auth then
    return http.basic_auth(user, pass)
  end
  -- Fall back to base64 (enc vs encode differs by version)
  if base64_ok and base64 then
    local f = base64.enc or base64.encode
    if f then
      return "Basic " .. f(("%s:%s"):format(user, pass))
    end
  end
  return nil
end

-- Decide HTTPS use: default to shortport.ssl() hint, allow override via arg
local function decide_https(host, port)
  local override = stdnse.get_script_args("dicom-web.ssl")
  if override ~= nil then
    local v = lc(override)
    return (v == "true" or v == "1" or v == "yes")
  end
  return shortport.ssl(host, port)
end

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  -- Common web ports
  return shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https"}, "tcp")(host, port)
end

action = function(host, port)
  local out = stdnse.output_table()
  local use_https = decide_https(host, port)

  -- helper to GET with hTLS flag (nselib/http expects 'ssl', not 'https')
    local ok, resp = pcall(http.get, host, port, path, {
      timeout = 5000,
      ssl     = https_flag,
      header  = hdr
    })
    return ok and resp or nil
  end

  -- If we accidentally talk HTTPS to HTTP (or vice versa), Orthanc returns 400 Bad Request.
  -- We'll flip the scheme once if we see that pattern.
  local function resilient_get(path, hdr)
    local resp = http_get(path, hdr, use_https)
    if resp and resp.status == 400 and body_has(resp.body, "Bad Request") then
      resp = http_get(path, hdr, not use_https)
    end
    return resp
  end

  -- ---------- Orthanc ----------
  do
    local user = stdnse.get_script_args("dicom-web.orthanc.user")
    local pass = stdnse.get_script_args("dicom-web.orthanc.pass")
    local hdr  = { ["Accept"] = "application/json" }
    local auth = make_basic_auth(user, pass)
    if auth then hdr["Authorization"] = auth end

    local resp = resilient_get("/system", hdr)

    if resp and resp.status then
      if resp.status == 401 or resp.status == 403 then
        table.insert(out, "Orthanc REST API: /system (authentication required)")
      elseif resp.status == 200 and resp.body and resp.body:find('"Name"%s*:%s*"Orthanc"') then
        local ver = resp.body:match('"Version"%s*:%s*"([^"]+)"')
        if ver and #ver > 0 then
          table.insert(out, ("Orthanc REST API: /system (version %s)"):format(ver))
        else
          table.insert(out, "Orthanc REST API: /system (reachable)")
        end
      end
    end
  end

  -- ---------- dcm4chee-arc UI2 ----------
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, p in ipairs(paths) do
      local resp = resilient_get(p, nil)
      if resp and resp.status and resp.body then
        local server = lc(hget(resp.header, "Server") or "")
        local loc    = lc(hget(resp.header, "Location") or "")
        local bdy    = lc(resp.body)
        local looks_like_arc =
          bdy:find("dcm4chee%-arc", 1, true) or
          bdy:find("dcm4che", 1, true) or
          server:find("wildfly", 1, true) or
          server:find("undertow", 1, true) or
          loc:find("/auth", 1, true)
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
    local resp = resilient_get("/", nil)
    if resp and resp.status == 200 and resp.body then
      if body_has(resp.body, "OHIF") or body_has(resp.body, "app-config.js") then
        table.insert(out, "OHIF Viewer: detected at /")
      end
    end
  end

  if next(out) == nil then return nil end
  return out
end