-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints:
--  - Orthanc REST API (/system) with version extraction
--  - OHIF Viewer (static UI check)
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

-- Optional base64 (API differs across Nmap versions)
local base64_ok, base64 = pcall(require, "base64")

-- ------------------------ helpers ------------------------

local function parse_ports_arg(s)
  if not s then return nil end
  local t = {}
  for p in tostring(s):gmatch("%d+") do t[tonumber(p)] = true end
  return next(t) and t or nil
end

local function to_s(v)
  if v == nil then return "" end
  local t = type(v)
  if t == "string" then return v end
  if t == "table" then
    -- best effort
    local parts = {}
    for i, x in ipairs(v) do parts[#parts+1] = tostring(x) end
    return table.concat(parts, ",")
  end
  return tostring(v)
end

local function lc(v) return to_s(v):lower() end

local function hget(h, k)
  if not h then return nil end
  return h[k] or h[string.lower(k)] or h[string.upper(k)]
end

local function body_has(b, needle)
  local bb = lc(b)
  return bb ~= "" and (bb:find(lc(needle), 1, true) ~= nil) or false
end

-- Build Authorization: Basic ... header safely across Nmap versions
local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  if http.basic_auth then
    return http.basic_auth(user, pass)
  end
  if base64_ok and base64 then
    local f = base64.enc or base64.encode
    if f then
      return "Basic " .. f(("%s:%s"):format(user, pass))
    end
  end
  return nil
end

-- Decide TLS explicitly: allow override; otherwise treat only 443/8443 as TLS
local function decide_tls(portnum)
  local override = stdnse.get_script_args("dicom-web.ssl")
  if override ~= nil then
    local v = lc(override)
    return (v == "true" or v == "1" or v == "yes")
  end
  return (portnum == 443 or portnum == 8443)
end

-- ------------------------ portrule ------------------------

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  -- Common web-ish ports we care about
  return shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https"}, "tcp")(host, port)
end

-- ------------------------ action ------------------------

action = function(host, port)
  local out = stdnse.output_table()
  local use_tls = decide_tls(port.number)

  -- helper: GET with TLS flag (nselib/http expects 'ssl', not 'https')
  local function http_get(path, hdr, want_tls)
    local opts = {
      timeout = 5000,
      ssl     = want_tls and true or false,
      header  = hdr
    }
    local ok, resp = pcall(http.get, host, port, path, opts)
    if not ok then return nil end
    -- normalize fields we use
    resp.status = tonumber(resp.status) or resp.status
    return resp
  end

  -- flip once if we sent TLS to HTTP (or vice versa) and got a typical 400
  local function resilient_get(path, hdr)
    local resp = http_get(path, hdr, use_tls)
    if resp and resp.status == 400 and body_has(resp.body, "bad request") then
      resp = http_get(path, hdr, not use_tls)
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
      elseif resp.status == 200 and type(resp.body) == "string" then
        if resp.body:find([["Name"%s*:%s*"Orthanc"]]) then
          local ver = resp.body:match([["Version"%s*:%s*"([^"]+)"]])
          if ver and ver ~= "" then
            table.insert(out, ("Orthanc REST API: /system (version %s)"):format(ver))
          else
            table.insert(out, "Orthanc REST API: /system (reachable)")
          end
        end
      end
    end
  end

  -- ---------- dcm4chee-arc UI2 ----------
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, p in ipairs(paths) do
      local resp = resilient_get(p, nil)
      if resp and resp.status and type(resp.body) == "string" then
        local server = lc(hget(resp.header, "Server") or "")
        local loc    = lc(hget(resp.header, "Location") or "")
        local bdy    = lc(resp.body)
        local looks_like_arc =
          (bdy:find("dcm4chee%-arc", 1, true) or
           bdy:find("dcm4che", 1, true) or
           server:find("wildfly", 1, true) or
           server:find("undertow", 1, true) or
           loc:find("/auth", 1, true))
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
    if resp and resp.status == 200 and type(resp.body) == "string" then
      -- OHIF images often serve a single index for any path; just look for common tokens
      if body_has(resp.body, "ohif") or body_has(resp.body, "app-config.js") then
        table.insert(out, "OHIF Viewer: detected at /")
      end
    end
  end

  if next(out) == nil then return nil end
  return out
end
