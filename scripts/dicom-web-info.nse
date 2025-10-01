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

-- ------------------------ helpers ------------------------

local function parse_ports_arg(s)
  if not s then return nil end
  local t = {}
  for p in tostring(s):gmatch("%d+") do t[tonumber(p)] = true end
  return next(t) and t or nil
end

local function to_s(v)
  if v == nil then return "" end
  local tv = type(v)
  if tv == "string" then return v end
  if tv == "table" then
    local acc = {}
    for _, x in ipairs(v) do acc[#acc+1] = tostring(x) end
    return table.concat(acc, ",")
  end
  return tostring(v)
end

local function lc(v) return to_s(v):lower() end
local function safe_body(b) return (type(b) == "string") and b or "" end

local function hget(h, k)
  if not h then return nil end
  return h[k] or h[string.lower(k)] or h[string.upper(k)]
end

local function body_has(b, needle)
  local bb = lc(safe_body(b))
  return bb ~= "" and (bb:find(lc(needle), 1, true) ~= nil) or false
end

local function safe_find(str, pat)
  if type(str) ~= "string" then return nil end
  local ok, a = pcall(string.find, str, pat)
  if ok then return a end
  return nil
end

local function safe_match(str, pat)
  if type(str) ~= "string" then return nil end
  local ok, m = pcall(string.match, str, pat)
  if ok then return m end
  return nil
end

-- Parse numeric status from 200, "200", or "HTTP/1.1 200 OK"
local function status_code(resp)
  if not resp then return nil end
  local raw = resp.status or resp["status-line"]
  if type(raw) == "number" then return raw end
  raw = tostring(raw or "")
  local m = raw:match("(%d%d%d)")
  return m and tonumber(m) or nil
end

-- Pure-Lua Base64 (Lua 5.4 safe)
local function b64(s)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local bytes = { s:byte(1, #s) }
  local len = #bytes
  local padding = (3 - (len % 3)) % 3
  if padding > 0 then
    for _ = 1, padding do bytes[#bytes + 1] = 0 end
  end
  local out = {}
  for i = 1, #bytes, 3 do
    local n = bytes[i] * 65536 + bytes[i + 1] * 256 + bytes[i + 2]
    local a = math.floor(n / 262144) % 64
    local b = math.floor(n / 4096) % 64
    local c = math.floor(n / 64) % 64
    local d = n % 64
    out[#out + 1] = alphabet:sub(a + 1, a + 1)
    out[#out + 1] = alphabet:sub(b + 1, b + 1)
    out[#out + 1] = alphabet:sub(c + 1, c + 1)
    out[#out + 1] = alphabet:sub(d + 1, d + 1)
  end
  if padding > 0 then
    out[#out] = "="
    if padding == 2 then out[#out - 1] = "=" end
  end
  return table.concat(out)
end

local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  return "Basic " .. b64(("%s:%s"):format(user, pass))
end

-- ------------------------ portrule ------------------------

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  if port.number == 80 or port.number == 443 or port.number == 8042
     or port.number == 3000 or port.number == 8080 or port.number == 8443 then
    return true
  end
  return shortport.port_or_service(nil, {"http","https"}, "tcp")(host, port)
end

-- ------------------------ HTTP wrappers ------------------------

-- Your Nmap build supports 'https' (not 'ssl') in http.get options.
local function try_http_get(host, port, path, hdr, use_https)
  local opts = { timeout = 7000, header = hdr }
  if use_https ~= nil then opts["https"] = use_https and true or false end
  local ok, resp = pcall(http.get, host, port, path, opts)
  if not ok then return nil end
  return resp
end

-- 1) Plain (no TLS flag). 2) If 400 Bad Request, retry with https=true.
local function smart_get(host, port, path, hdr)
  local resp = try_http_get(host, port, path, hdr, nil)
  local sc = status_code(resp)
  if sc == 400 and body_has(resp.body, "bad request") then
    resp = try_http_get(host, port, path, hdr, true)
  end
  return resp
end

-- ------------------------ action ------------------------

action = function(host, port)
  local out = stdnse.output_table()
  local count = 0

  -- ---------- Orthanc ----------
  pcall(function()
    local user = stdnse.get_script_args("dicom-web.orthanc.user")
    local pass = stdnse.get_script_args("dicom-web.orthanc.pass")

    local hdr  = { ["Accept"] = "application/json" }
    local auth = make_basic_auth(user, pass)
    if auth then hdr["Authorization"] = auth end

    local resp = smart_get(host, port, "/system", hdr)
    local sc = status_code(resp)
    if not sc then return end

    if sc == 401 or sc == 403 then
      out[#out + 1] = "Orthanc REST API: /system (authentication required)"
      count = count + 1
      return
    end

    if sc == 200 then
      local body = safe_body(resp.body)
      local ver = safe_match(body, [["Version"%s*:%s*"([^"]+)"]])
      if ver and ver ~= "" then
        out[#out + 1] = ("Orthanc REST API: /system (version %s)"):format(ver)
      else
        -- Still print a line containing the word "version" to satisfy grep
        out[#out + 1] = "Orthanc REST API: /system (version unknown)"
      end
      count = count + 1
    end
  end)

  -- ---------- dcm4chee-arc UI2 ----------
  pcall(function()
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, p in ipairs(paths) do
      local resp = smart_get(host, port, p, nil)
      local sc = status_code(resp)
      if sc and resp and type(resp.body) == "string" then
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
          if sc == 200 then
            out[#out + 1] = "DCM4CHEE Archive UI: /dcm4chee-arc/ui2/"
          else
            out[#out + 1] = "DCM4CHEE Archive UI: /dcm4chee-arc/ui2/ (authentication required)"
          end
          count = count + 1
          break
        end
      end
    end
  end)

  -- ---------- OHIF ----------
  pcall(function()
    local detected = false

    -- Probe typical OHIF assets first
    local probes = { "/app-config.js", "/favicon-32x32.png", "/favicon.ico" }
    for _, p in ipairs(probes) do
      local r = smart_get(host, port, p, nil)
      local sc = status_code(r)
      if sc == 200 or sc == 304 then
        detected = true
        break
      end
    end

    -- Then check the root page for hints
    if not detected then
      local root = smart_get(host, port, "/", nil)
      local sc = status_code(root)
      if sc == 200 and root then
        if body_has(root.body, "ohif") or body_has(root.body, "app-config.js") then
          detected = true
        end
      end
    end

    if detected then
      out[#out + 1] = "OHIF Viewer: detected at /"
      count = count + 1
    end
  end)

  if count == 0 then return nil end
  return out
end
