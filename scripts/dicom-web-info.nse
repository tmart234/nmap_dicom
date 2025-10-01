-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints:
--  - Orthanc REST API (/system) with version extraction
--  - OHIF Viewer (handles empty/generic index by probing /app-config.js)
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

-- optional base64 (API differs across Nmap versions)
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
    local acc = {}
    for i, x in ipairs(v) do acc[#acc+1] = tostring(x) end
    return table.concat(acc, ",")
  end
  return tostring(v)
end

local function lc(v)
  return to_s(v):lower()
end

local function hget(h, k)
  if not h then return nil end
  return h[k] or h[string.lower(k)] or h[string.upper(k)]
end

local function safe_body(b)
  if type(b) == "string" then return b end
  return ""
end

local function body_has(b, needle)
  local bb = lc(safe_body(b))
  return bb ~= "" and (bb:find(lc(needle), 1, true) ~= nil) or false
end

local function safe_find(str, pat)
  if type(str) ~= "string" then return nil end
  local ok, a, b = pcall(string.find, str, pat)
  if ok then return a, b end
  return nil
end

local function safe_match(str, pat)
  if type(str) ~= "string" then return nil end
  local ok, m = pcall(string.match, str, pat)
  if ok then return m end
  return nil
end

-- Build Authorization: Basic ... header safely across Nmap versions
local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  if http.basic_auth then
    local ok, val = pcall(http.basic_auth, user, pass)
    if ok and type(val) == "string" then return val end
  end
  if base64_ok and base64 then
    local f = base64.enc or base64.encode
    if f then
      local ok, enc = pcall(f, ("%s:%s"):format(user, pass))
      if ok and type(enc) == "string" then
        return "Basic " .. enc
      end
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
  -- Explicitly include our common web-ish ports regardless of service name
  if port.number == 80 or port.number == 443 or port.number == 8042
     or port.number == 3000 or port.number == 8080 or port.number == 8443 then
    return true
  end
  -- Fallback to service guess
  return shortport.port_or_service(nil, {"http","https"}, "tcp")(host, port)
end

-- ------------------------ action ------------------------

action = function(host, port)
  local out = stdnse.output_table()
  local use_tls = decide_tls(port.number)

  -- helper: GET with TLS flag (nselib/http expects 'ssl', not 'https')
  local function http_get(path, hdr, want_tls)
    local opts = {
      timeout = 7000,
      ssl     = (want_tls and true or false),
      header  = hdr
    }
    local ok, resp = pcall(http.get, host, port, path, opts)
    if not ok then return nil end
    if resp then
      resp.status = tonumber(resp.status) or resp.status
    end
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
    local ok = pcall(function()
      local user = stdnse.get_script_args("dicom-web.orthanc.user")
      local pass = stdnse.get_script_args("dicom-web.orthanc.pass")
      local hdr  = { ["Accept"] = "application/json" }
      local auth = make_basic_auth(user, pass)
      if auth then hdr["Authorization"] = auth end

      local resp = resilient_get("/system", hdr)
      if not (resp and resp.status) then return end

      if resp.status == 401 or resp.status == 403 then
        table.insert(out, "Orthanc REST API: /system (authentication required)")
        return
      end

      if resp.status == 200 then
        local body = safe_body(resp.body)
        local has_name = safe_find(body, [["Name"%s*:%s*"Orthanc"]]) ~= nil
        if has_name then
          local ver = safe_match(body, [["Version"%s*:%s*"([^"]+)"]])
          if ver and ver ~= "" then
            table.insert(out, ("Orthanc REST API: /system (version %s)"):format(ver))
          else
            table.insert(out, "Orthanc REST API: /system (reachable)")
          end
        end
      end
    end)
    -- ignore ok==false; we hard-fail nothing here
  end

  -- ---------- dcm4chee-arc UI2 ----------
  do
    local ok = pcall(function()
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
    end)
    -- ignore ok==false
  end

  -- ---------- OHIF ----------
  do
    local ok = pcall(function()
      -- 1) Try root
      local root = resilient_get("/", nil)
      local detected = false
      if root and root.status == 200 then
        if body_has(root.body, "ohif") or body_has(root.body, "app-config.js") then
          detected = true
        end
      end

      -- 2) If not sure, probe common OHIF assets even when app-config is empty
      if not detected then
        local probes = {
          "/app-config.js",
          "/favicon-32x32.png",
          "/favicon.ico"
        }
        for _, p in ipairs(probes) do
          local r = resilient_get(p, nil)
          if r and (r.status == 200 or r.status == 304) then
            -- Accept an empty app-config.js as a positive signal (OHIF container prints that in logs)
            detected = true
            break
          end
        end
      end

      if detected then
        table.insert(out, "OHIF Viewer: detected at /")
      end
    end)
    -- ignore ok==false
  end

  if next(out) == nil then return nil end
  return out
end
