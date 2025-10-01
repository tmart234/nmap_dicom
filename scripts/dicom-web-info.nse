-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) + version
--   - DICOMweb bases (Orthanc: /dicom-web, dcm4chee: /dcm4chee-arc/rs)
--   - OHIF viewer
--
-- Security checks (non-intrusive):
--   - HTTP used instead of HTTPS
--   - Unauthenticated QIDO-RS listing (/studies?limit=1)
--   - Risky CORS headers (ACAO: * with ACC: true)
--   - (Advisory) STOW-RS seems allowed via OPTIONS without auth (no POSTs performed)
--   - (Opt-in) Orthanc default credentials accepted (orthanc:orthanc)
--
-- Usage:
--   nmap -p 8042,3000,8080 --script dicom-web-info [--script-args ...] <target>
--
-- Script args (all optional):
--   dicom-web.qido-test=true|false          (default true)
--   dicom-web.cors-test=true|false          (default true)
--   dicom-web.stow-test=true|false          (default false)
--   dicom-web.try-defaults=true|false       (default false)
--   dicom-web.orthanc.user=<user>           (default none)
--   dicom-web.orthanc.pass=<pass>           (default none)
--   dicom-web.ssl=true|false                (force https vs autodetect)
--   dicom-web.ports=8042,3000,8080          (limit portrule)
--
-- Examples:
--   nmap -p 8042 --script dicom-web-info --script-args dicom-web.try-defaults=true localhost
--   nmap -p 8042,8080 --script dicom-web-info --script-args dicom-web.qido-test=false <host>
--
author = "Tyler M (extended)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version", "vuln"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- optional base64 (API differs across Nmap versions)
local base64_ok, base64 = pcall(require, "base64")

-- -------------------- small helpers --------------------

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

local function truthy(v)
  if v == nil then return false end
  local s = lc(v)
  return (s == "1" or s == "true" or s == "yes" or s == "on")
end

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

-- Decide HTTPS use: default to shortport.ssl() hint, allow override via arg
local function decide_https(host, port)
  local override = stdnse.get_script_args("dicom-web.ssl")
  if override ~= nil then
    return truthy(override)
  end
  return shortport.ssl(host, port)
end

-- -------------------- portrule --------------------

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  -- Common web ports
  return shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https"}, "tcp")(host, port)
end

-- -------------------- action --------------------

action = function(host, port)
  local out   = stdnse.output_table()
  local warn  = {}
  local use_https = decide_https(host, port)

  -- Get toggles
  local do_qido  = truthy(stdnse.get_script_args("dicom-web.qido-test") or "true")
  local do_cors  = truthy(stdnse.get_script_args("dicom-web.cors-test") or "true")
  local do_stow  = truthy(stdnse.get_script_args("dicom-web.stow-test") or "false")
  local try_defs = truthy(stdnse.get_script_args("dicom-web.try-defaults") or "false")

  -- helper to GET with correct option key (nselib/http expects 'https')
  local function http_get(path, hdr, https_flag)
    local ok, resp = pcall(http.get, host, port, path, {
      timeout = 7000,
      https   = https_flag,
      header  = hdr
    })
    if not ok then return nil end
    return resp
  end

  -- OPTIONS helper
  local function http_options(path, hdr, https_flag)
    local ok, resp = pcall(http.options, host, port, path, {
      timeout = 7000,
      https   = https_flag,
      header  = hdr
    })
    if not ok then return nil end
    return resp
  end

  -- Flip once on Orthanc’s 400/BAD REQUEST if scheme is wrong
  local function resilient_get(path, hdr)
    local resp = http_get(path, hdr, use_https)
    if resp and resp.status == 400 and body_has(resp.body, "bad request") then
      resp = http_get(path, hdr, not use_https)
    end
    return resp
  end

  local function resilient_options(path, hdr)
    local resp = http_options(path, hdr, use_https)
    if resp and resp.status == 400 and body_has(resp.body, "bad request") then
      resp = http_options(path, hdr, not use_https)
    end
    return resp
  end

  -- -------------------- baseline detections --------------------

  -- TLS/HTTP check
  if not use_https then
    table.insert(warn, "Warning: HTTP (no TLS) detected")
  end

  -- Orthanc detection + version + auth posture
  local orthanc_seen, orthanc_auth, orthanc_version = false, "unknown", nil
  do
    local u = stdnse.get_script_args("dicom-web.orthanc.user")
    local p = stdnse.get_script_args("dicom-web.orthanc.pass")
    local hdr = { ["Accept"] = "application/json" }
    local auth = make_basic_auth(u, p)
    -- First, try without auth
    local r_no = resilient_get("/system", hdr)
    if r_no and r_no.status then
      if r_no.status == 200 and r_no.body and body_has(r_no.body, '"name"') and body_has(r_no.body, "orthanc") then
        orthanc_seen = true
        orthanc_auth = "no-auth"
        orthanc_version = r_no.body:match('"version"%s*:%s*"([^"]+)"') or
                          r_no.body:match('"Version"%s*:%s*"([^"]+)"')
      elseif r_no.status == 401 or r_no.status == 403 then
        -- Try with provided creds
        orthanc_seen = true
        orthanc_auth = "auth-required"
        if auth then
          local hdr2 = { ["Accept"] = "application/json", ["Authorization"] = auth }
          local r_yes = resilient_get("/system", hdr2)
          if r_yes and r_yes.status == 200 and r_yes.body then
            orthanc_version = r_yes.body:match('"version"%s*:%s*"([^"]+)"') or
                              r_yes.body:match('"Version"%s*:%s*"([^"]+)"')
          end
        end
        -- Opt-in: Try default creds only if we confirmed auth is required
        if try_defs then
          local def_auth = make_basic_auth("orthanc", "orthanc")
          if def_auth then
            local hdr3 = { ["Accept"] = "application/json", ["Authorization"] = def_auth }
            local r_def = resilient_get("/system", hdr3)
            if r_def and r_def.status == 200 then
              table.insert(warn, "Insecure: Orthanc accepts default credentials (orthanc:orthanc)")
              if not orthanc_version and r_def.body then
                orthanc_version = r_def.body:match('"version"%s*:%s*"([^"]+)"') or
                                  r_def.body:match('"Version"%s*:%s*"([^"]+)"')
              end
            end
          end
        end
      end
    end
    if orthanc_seen then
      if orthanc_version then
        table.insert(out, ("Orthanc REST API: /system (version %s)"):format(orthanc_version))
      else
        table.insert(out, "Orthanc REST API: /system (version unknown)")
      end
      if orthanc_auth == "no-auth" then
        table.insert(warn, "Insecure: Orthanc /system reachable without authentication")
      end
    end
  end

  -- dcm4chee UI (best-effort)
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, pth in ipairs(paths) do
      local r = resilient_get(pth, nil)
      if r and r.status and r.body then
        local server = lc(hget(r.header, "Server") or "")
        local loc    = lc(hget(r.header, "Location") or "")
        local bdy    = lc(r.body)
        local looks =
          bdy:find("dcm4chee%-arc", 1, true) or
          bdy:find("dcm4che", 1, true) or
          server:find("wildfly", 1, true) or
          server:find("undertow", 1, true) or
          loc:find("/auth", 1, true)
        if looks then
          table.insert(out, "DCM4CHEE Archive UI: /dcm4chee-arc/ui2/")
          break
        end
      end
    end
  end

  -- OHIF detection
  local ohif_seen = false
  do
    local r = resilient_get("/", nil)
    if r and r.status == 200 and r.body then
      if body_has(r.body, "ohif") or body_has(r.body, "app-config.js") then
        table.insert(out, "OHIF Viewer: detected at /")
        ohif_seen = true
      end
    end
  end

  -- -------------------- DICOMweb checks --------------------
  -- We’ll try Orthanc and dcm4chee typical bases.
  local bases = {
    {name="Orthanc DICOMweb", base="/dicom-web"},
    {name="dcm4chee DICOMweb", base="/dcm4chee-arc/rs"}
  }

  local function any_qido_open()
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies?limit=1"
      local hdr = { ["Accept"] = "application/dicom+json" }
      local r = resilient_get(path, hdr)
      if r and r.status then
        if r.status == 200 and r.body and (#r.body > 0) then
          table.insert(warn, ("Insecure: Unauthenticated QIDO-RS listing at %s (GET %s)"):format(b.name, path))
          return true
        elseif r.status == 401 or r.status == 403 then
          -- secured, fine
        elseif r.status == 404 then
          -- not present here
        end
      end
    end
    return false
  end

  local function check_cors()
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies?limit=0"
      local r = resilient_options(path, { ["Origin"] = "https://example.com", ["Access-Control-Request-Method"] = "GET" })
      if r and r.header then
        local acao = hget(r.header, "Access-Control-Allow-Origin")
        local acc  = hget(r.header, "Access-Control-Allow-Credentials")
        if acao and lc(acao) == "*" and acc and truthy(acc) then
          table.insert(warn, ("Warning: Risky CORS at %s (ACAO: * with credentials=true)"):format(b.base))
        end
      end
    end
  end

  local function stow_options_without_auth()
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies"
      local r = resilient_options(path, { ["Access-Control-Request-Method"] = "POST" })
      if r and r.header then
        local allow = (hget(r.header, "Allow") or "") .. "," .. (hget(r.header, "Access-Control-Allow-Methods") or "")
        if lc(allow):find("post", 1, true) and (not (r.status == 401 or r.status == 403)) then
          table.insert(warn, ("Advisory: STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(path))
        end
      end
    end
  end

  if do_qido then any_qido_open() end
  if do_cors then check_cors() end
  if do_stow then stow_options_without_auth() end

  -- -------------------- output --------------------
  for _, w in ipairs(warn) do
    table.insert(out, w)
  end

  if #out == 0 then return nil end
  return out
end
