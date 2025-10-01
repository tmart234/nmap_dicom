-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) + (best-effort) version
--   - DICOMweb bases (Orthanc: /dicom-web, dcm4chee: /dcm4chee-arc/rs)
--   - OHIF viewer
--
-- Security checks (non-intrusive):
--   - HTTP used instead of HTTPS
--   - Unauthenticated QIDO-RS listing (/studies?limit=1) with DICOM JSON
--   - Risky CORS (ACAO: * with credentials=true)
--   - (Advisory) STOW-RS appears allowed via OPTIONS without auth
--   - (Opt-in) Orthanc default creds accepted (orthanc:orthanc)
--
-- Script args (all optional):
--   dicom-web.qido-test=true|false          (default true)
--   dicom-web.cors-test=true|false          (default true)
--   dicom-web.stow-test=true|false          (default false)
--   dicom-web.try-defaults=true|false       (default false)
--   dicom-web.orthanc.user=<user>           (default none)
--   dicom-web.orthanc.pass=<pass>           (default none)
--   dicom-web.ports=8042,3000,8080          (limit portrule)
--
-- Examples:
--   nmap -p 8042,3000 --script dicom-web-info localhost
--   nmap -p 8042 --script dicom-web-info --script-args dicom-web.try-defaults=true localhost
--
author = "Tyler M (extended)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version", "vuln"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- optional base64 module
local base64_ok, base64 = pcall(require, "base64")

-- -------------------- helpers --------------------

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

-- Build Authorization: Basic ... (no http.basic_auth to satisfy strict.lua)
local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  if base64_ok and base64 then
    local enc = base64.enc or base64.encode
    if enc then return "Basic " .. enc(("%s:%s"):format(user, pass)) end
  end
  return nil
end

-- simple wrappers around http.generic_request (no unknown options keys!)
local function http_get(host, port, path, hdr)
  local ok, resp = pcall(http.generic_request, host, port, "GET", path, {
    header = hdr or {},
    timeout = 7000,
  })
  if not ok then return nil end
  return resp
end

local function http_options(host, port, path, hdr)
  local ok, resp = pcall(http.generic_request, host, port, "OPTIONS", path, {
    header = hdr or {},
    timeout = 7000,
  })
  if not ok then return nil end
  return resp
end

-- -------------------- portrule --------------------

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end
  return shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https"}, "tcp")(host, port)
end

-- -------------------- action --------------------

action = function(host, port)
  local out   = stdnse.output_table()
  local warn  = {}

  -- toggles
  local do_qido  = truthy(stdnse.get_script_args("dicom-web.qido-test") or "true")
  local do_cors  = truthy(stdnse.get_script_args("dicom-web.cors-test") or "true")
  local do_stow  = truthy(stdnse.get_script_args("dicom-web.stow-test") or "false")
  local try_defs = truthy(stdnse.get_script_args("dicom-web.try-defaults") or "false")

  -- TLS/HTTP hint
  local is_tls = (port.tunnel == "ssl") or shortport.ssl(host, port)
  if not is_tls then
    table.insert(warn, "Warning: HTTP (no TLS) detected")
  end

  -- -------- Orthanc detection --------
  local orthanc_seen, orthanc_auth, orthanc_version = false, "unknown", nil
  do
    local hdr_json = { ["Accept"] = "application/json" }
    local r_no = http_get(host, port, "/system", hdr_json)
    if r_no and r_no.status then
      if r_no.status == 200 and r_no.body and (body_has(r_no.body, '"name"') and body_has(r_no.body, "orthanc")) then
        orthanc_seen = true
        orthanc_auth = "no-auth"
        orthanc_version = r_no.body:match('"version"%s*:%s*"([^"]+)"') or
                          r_no.body:match('"Version"%s*:%s*"([^"]+)"')
      elseif r_no.status == 401 or r_no.status == 403 then
        orthanc_seen = true
        orthanc_auth = "auth-required"
        -- user-supplied creds
        local u = stdnse.get_script_args("dicom-web.orthanc.user")
        local p = stdnse.get_script_args("dicom-web.orthanc.pass")
        local auth = make_basic_auth(u, p)
        if auth then
          local r_yes = http_get(host, port, "/system", { ["Accept"]="application/json", ["Authorization"]=auth })
          if r_yes and r_yes.status == 200 and r_yes.body then
            orthanc_version = r_yes.body:match('"version"%s*:%s*"([^"]+)"') or
                              r_yes.body:match('"Version"%s*:%s*"([^"]+)"')
          end
        end
        -- optional default creds probe
        if try_defs then
          local def_auth = make_basic_auth("orthanc","orthanc")
          if def_auth then
            local r_def = http_get(host, port, "/system", { ["Accept"]="application/json", ["Authorization"]=def_auth })
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

  -- -------- dcm4chee UI best-effort --------
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, pth in ipairs(paths) do
      local r = http_get(host, port, pth)
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

  -- -------- OHIF detection (tolerant) --------
  do
    local r = http_get(host, port, "/")
    local ohif = false
    if r and r.status == 200 and r.body then
      if body_has(r.body, "ohif") or body_has(r.body, "app-config.js") then
        ohif = true
      end
    end
    if not ohif then
      local r2 = http_get(host, port, "/app-config.js")
      if r2 and r2.status == 200 and r2.body and #r2.body > 0 then
        ohif = true
      end
    end
    if ohif then
      table.insert(out, "OHIF Viewer: detected at /")
    end
  end

  -- -------- DICOMweb checks --------
  local bases = {
    {name="Orthanc DICOMweb", base="/dicom-web"},
    {name="dcm4chee DICOMweb", base="/dcm4chee-arc/rs"},
  }

  local function is_dicom_json(r)
    if not (r and r.status == 200 and r.body) then return false end
    local ct = lc(hget(r.header, "Content-Type") or "")
    if ct:find("application/dicom%+json", 1, false) then return true end
    -- heuristic tags/fields commonly present in DICOM JSON
    return body_has(r.body, '"StudyInstanceUID"')
        or body_has(r.body, '"SeriesInstanceUID"')
        or body_has(r.body, '"SOPInstanceUID"')
        or body_has(r.body, '"MainDicomTags"')
  end

  if truthy(stdnse.get_script_args("dicom-web.qido-test") or "true") then
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies?limit=1"
      local r = http_get(host, port, path, { ["Accept"]="application/dicom+json" })
      if r then
        if is_dicom_json(r) then
          table.insert(warn, ("Insecure: Unauthenticated QIDO-RS listing at %s (GET %s)"):format(b.name, path))
        elseif r.status == 401 or r.status == 403 then
          -- secured, fine
        end
      end
    end
  end

  if truthy(stdnse.get_script_args("dicom-web.cors-test") or "true") then
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies?limit=0"
      local r = http_options(host, port, path, {
        ["Origin"] = "https://example.com",
        ["Access-Control-Request-Method"] = "GET",
      })
      if r and r.header then
        local acao = hget(r.header, "Access-Control-Allow-Origin")
        local acc  = hget(r.header, "Access-Control-Allow-Credentials")
        if (acao and lc(acao) == "*") and (acc and truthy(acc)) then
          table.insert(warn, ("Warning: Risky CORS at %s (ACAO: * with credentials=true)"):format(b.base))
        end
      end
    end
  end

  if truthy(stdnse.get_script_args("dicom-web.stow-test") or "false") then
    for _, b in ipairs(bases) do
      local path = b.base .. "/studies"
      local r = http_options(host, port, path, { ["Access-Control-Request-Method"] = "POST" })
      if r and r.header then
        local allow = (hget(r.header, "Allow") or "") .. "," .. (hget(r.header, "Access-Control-Allow-Methods") or "")
        if lc(allow):find("post", 1, true) and not (r.status == 401 or r.status == 403) then
          table.insert(warn, ("Advisory: STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(path))
        end
      end
    end
  end

  for _, w in ipairs(warn) do table.insert(out, w) end
  if #out == 0 then return nil end
  return out
end
