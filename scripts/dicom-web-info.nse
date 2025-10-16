---
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) and (best-effort) version
--   - DICOMweb bases (Orthanc: /dicom-web; dcm4chee: /dcm4chee-arc/rs; dcm4chee AET: /dcm4chee-arc/aets/DCM4CHEE/rs)
--   - OHIF viewer
--
-- Security checks (non-intrusive):
--   - http instead of https (suppressed if cleanly upgraded to same-host https)
--   - Unauthenticated QIDO-RS listing (/studies?limit=1) with DICOM JSON
--     (tries Accept: application/dicom+json, then falls back to application/json on 406)
--   - risky CORS (ACAO: * with credentials=true)
--   - (advisory) STOW-RS appears allowed via OPTIONS without auth
--   - (advisory) missing Content-Security-Policy on known UIs
--   - (info) WWW-Authenticate scheme on 401 (e.g., Basic/Bearer)
--   - (default) Orthanc default creds accepted (orthanc:orthanc); disable with dicom-web.no-defaults=true
--
-- @usage
-- nmap -p 8042,3000 --script dicom-web-info <target>
--
-- @args dicom-web.qido-test    (bool)  Probe QIDO unauth listing (default: true)
-- @args dicom-web.cors-test    (bool)  Probe CORS preflight (default: true)
-- @args dicom-web.stow-test    (bool)  Probe STOW via OPTIONS (advisory) (default: false)
-- @args dicom-web.no-defaults  (bool)  Do NOT try Orthanc default creds (default: false)
-- @args dicom-web.ports        (str)   Comma-list to limit portrule (e.g., "8042,3000,8080")
--
-- @output
-- PORT     STATE SERVICE
-- 8042/tcp open  http
-- | dicom-web-info:
-- |   orthanc:
-- |     path: /system
-- |     version: 1.12.9
-- |     auth: auth-required
-- |     www-authenticate: Basic realm="Orthanc Secure Area"
-- |   ui:
-- |     ohif: /
-- |   dicomweb:
-- |     bases:
-- |       - base: /dicom-web
-- |         impl: orthanc
-- |         qido: secured
-- |       - base: /dcm4chee-arc/rs
-- |         impl: dcm4chee
-- |         qido: secured
-- |   warnings:
-- |     warning: http (no TLS) detected
-- |_    advisory: OHIF root missing Content-Security-Policy
--
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- optional base64 module provided by Nmap (nselib/base64.lua)
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

local function make_basic_auth(user, pass)
  if not (user and pass) then return nil end
  if base64_ok and base64 then
    local enc = base64.enc or base64.encode
    if enc then return "Basic " .. enc(("%s:%s"):format(user, pass)) end
  end
  return nil
end

-- minimal wrappers around http.generic_request with TLS and single-hop redirect follow

local function _generic(host, port, method, path, hdr)
  local opts = { header = hdr or {}, timeout = 7000 }
  if port.tunnel == "ssl" then opts.ssl = true end -- explicit TLS
  local ok, resp = pcall(http.generic_request, host, port, method, path, opts)
  if not ok then return nil end
  return resp
end

local function follow_redirect_once(host, port, resp, hdr)
  if not resp or not resp.status then return resp end
  if resp.status == 301 or resp.status == 302 or resp.status == 307 or resp.status == 308 then
    local loc = hget(resp.header, "Location")
    if loc then
      if loc:sub(1,1) == "/" then
        return _generic(host, port, "GET", loc, hdr)
      end
      local _, hostpart, path = loc:match("^(https?)://([^/]+)(/.*)$")
      if hostpart and path then
        if hostpart == host.targetname or hostpart == host.ip then
          return _generic(host, port, "GET", path, hdr)
        end
      end
    end
  end
  return resp
end

local function http_get(host, port, path, hdr)
  local r = _generic(host, port, "GET", path, hdr)
  return follow_redirect_once(host, port, r, hdr)
end

local function http_options(host, port, path, hdr)
  local r = _generic(host, port, "OPTIONS", path, hdr)
  return follow_redirect_once(host, port, r, hdr)
end

-- ---------- lightweight memoization for GET/OPTIONS ----------

local _cache = {}
local function cache_key(method, path, hdr)
  local a = ""
  if hdr then
    -- only include a couple of headers we vary on
    local acc = hdr["Accept"] or hdr["accept"] or ""
    local acrm = hdr["Access-Control-Request-Method"] or ""
    local origin = hdr["Origin"] or ""
    a = acc .. "|" .. acrm .. "|" .. origin
  end
  return method .. "|" .. path .. "|" .. a
end

local function http_get_cached(host, port, path, hdr)
  local k = cache_key("GET", path, hdr)
  if _cache[k] ~= nil then return _cache[k] end
  local r = http_get(host, port, path, hdr)
  _cache[k] = r
  return r
end

local function http_options_cached(host, port, path, hdr)
  local k = cache_key("OPTIONS", path, hdr)
  if _cache[k] ~= nil then return _cache[k] end
  local r = http_options(host, port, path, hdr)
  _cache[k] = r
  return r
end

-- -------------------- portrule --------------------

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set then return set[port.number] == true end
  return shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https"}, "tcp")(host, port)
end

-- -------------------- action --------------------

action = function(host, port)
  local out   = stdnse.output_table()

  -- stable, pretty warnings
  local warn = stdnse.output_table()
  local function addwarn(s) table.insert(warn, s) end

  -- toggles (kept minimal)
  local do_qido   = truthy(stdnse.get_script_args("dicom-web.qido-test") or "true")
  local do_cors   = truthy(stdnse.get_script_args("dicom-web.cors-test") or "true")
  local do_stow   = truthy(stdnse.get_script_args("dicom-web.stow-test") or "false")
  local no_defs   = truthy(stdnse.get_script_args("dicom-web.no-defaults") or "false")

  -- structures
  out.orthanc  = stdnse.output_table()
  out.ui       = stdnse.output_table()
  out.dicomweb = stdnse.output_table()
  out.dicomweb.bases = {}

  -- Reduce false positives: treat clean HTTP→HTTPS redirect to same host as acceptable
  local function is_https_redirect()
    local r = http_get_cached(host, port, "/")
    if not (r and (r.status == 301 or r.status == 302)) then return false end
    local loc = hget(r.header, "Location")
    if not loc then return false end
    local scheme, hostpart = loc:match("^(https?)://([^/]+)")
    if scheme ~= "https" then return false end
    return (hostpart == host.targetname or hostpart == host.ip)
  end

  -- TLS hint
  if port.tunnel ~= "ssl" then
    if not is_https_redirect() then
      addwarn("warning: http (no TLS) detected")
    end
  end

  -- -------- Orthanc detection --------
  local orthanc_seen, orthanc_auth, orthanc_version = false, "unknown", nil
  local orthanc_wa = nil
  do
    local hdr_json = { ["Accept"] = "application/json" }
    local r_no = http_get_cached(host, port, "/system", hdr_json)
    if r_no and r_no.status then
      if r_no.status == 200 and r_no.body and (body_has(r_no.body, '"name"') and body_has(r_no.body, "orthanc")) then
        orthanc_seen = true
        orthanc_auth = "no-auth"
        orthanc_version = r_no.body:match('"version"%s*:%s*"([^"]+)"') or
                          r_no.body:match('"Version"%s*:%s*"([^"]+)"')
      elseif r_no.status == 401 or r_no.status == 403 then
        orthanc_seen = true
        orthanc_auth = "auth-required"
        orthanc_wa = hget(r_no.header, "WWW-Authenticate")
        -- default creds probe only if Basic is advertised
        local wa_lc = lc(orthanc_wa or "")
        if not no_defs and wa_lc:find("basic", 1, true) then
          local def_auth = make_basic_auth("orthanc","orthanc")
          if def_auth then
            local r_def = http_get_cached(host, port, "/system", { ["Accept"]="application/json", ["Authorization"]=def_auth })
            if r_def and r_def.status == 200 and r_def.body then
              addwarn("warning: Orthanc accepts default credentials (orthanc:orthanc)")
              orthanc_version = r_def.body:match('"version"%s*:%s*"([^"]+)"') or
                                r_def.body:match('"Version"%s*:%s*"([^"]+)"') or orthanc_version
            end
          end
        end
      end
    end
    if orthanc_seen then
      out.orthanc.path    = "/system"
      out.orthanc.version = orthanc_version or "unknown"
      out.orthanc.auth    = orthanc_auth
      if orthanc_wa then out.orthanc["www-authenticate"] = orthanc_wa end
      if orthanc_auth == "no-auth" then
        addwarn("warning: Orthanc /system reachable without authentication")
      end
    end
  end

  -- -------- dcm4chee UI (best-effort) --------
  do
    local paths = {"/dcm4chee-arc/ui2/index.html", "/dcm4chee-arc/ui2/"}
    for _, pth in ipairs(paths) do
      local r = http_get_cached(host, port, pth)
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
          out.ui["dcm4chee-arc-ui"] = "/dcm4chee-arc/ui2/"
          if not hget(r.header, "Content-Security-Policy") then
            addwarn("advisory: DCM4CHEE UI missing Content-Security-Policy")
          end
          break
        end
      end
    end
  end

  -- -------- OHIF detection (tight; common mounts) --------
  do
    local ohif = false
    local mount = nil
    local candidate_paths = { "/", "/viewer/", "/ohif/" }
    for _, p in ipairs(candidate_paths) do
      local r = http_get_cached(host, port, p)
      if r and r.status == 200 and r.body then
        if body_has(r.body, "data-cy-root") or body_has(r.body, "ohif") or body_has(r.body, "app-config.js") then
          ohif = true
          mount = p
          if not hget(r.header, "Content-Security-Policy") then
            addwarn("advisory: OHIF root missing Content-Security-Policy")
          end
          break
        end
      end
    end
    if not ohif then
      local r2 = http_get_cached(host, port, "/app-config.js")
      if r2 and r2.status == 200 and r2.body and #r2.body > 0 then
        if body_has(r2.body, "window.config") or body_has(r2.body, "getAppConfig") then
          ohif = true
          mount = "/"
        end
      end
    end
    if ohif then
      out.ui["ohif"] = mount or "/"
    end
  end

  -- -------- DICOMweb checks --------
  local bases = {
    {impl="orthanc",   base="/dicom-web"},
    {impl="dcm4chee",  base="/dcm4chee-arc/rs"},
    {impl="dcm4chee",  base="/dcm4chee-arc/aets/DCM4CHEE/rs"}, -- common AET route; ok if 404
  }
  -- stable CI diffs
  table.sort(bases, function(a,b) return a.base < b.base end)

  local function is_dicom_json(r)
    if not (r and r.status == 200 and r.body) then return false end
    local ct = lc(hget(r.header, "Content-Type") or "")
    if ct:find("application/dicom%+json", 1, false) then return true end
    return body_has(r.body, '"StudyInstanceUID"')
        or body_has(r.body, '"SeriesInstanceUID"')
        or body_has(r.body, '"SOPInstanceUID"')
        or body_has(r.body, '"MainDicomTags"')
  end

  local function qido_try_paths(base)
    local candidates = {
      base .. "/studies?limit=1",
      base .. "/studies?offset=0&limit=1",
    }
    for _, path in ipairs(candidates) do
      local r = http_get_cached(host, port, path, { ["Accept"]="application/dicom+json" })
      if r and r.status == 406 then
        r = http_get_cached(host, port, path, { ["Accept"]="application/json" })
      end
      if r then
        return r, path
      end
    end
    return nil, nil
  end

  for _, b in ipairs(bases) do
    -- Ordered per-base output
    local info = stdnse.output_table()
    info.base = b.base
    info.impl = b.impl

    -- Reachability (+ Orthanc plugin index hint)
    local r = http_get_cached(host, port, b.base .. "/")
    if r and (r.status == 200 or r.status == 204 or r.status == 401 or r.status == 403) then
      info.reachable = true
      if b.base == "/dicom-web" and r.status == 200 then
        info["orthanc-plugin-enabled"] = true
      end
    end

    -- QIDO (set only when meaningful; include 429/503)
    if do_qido then
      local rq, used_path = qido_try_paths(b.base)
      if rq then
        if is_dicom_json(rq) then
          info.qido = "open"
          addwarn(("warning: unauthenticated QIDO-RS listing at %s (GET %s)"):format(b.base, used_path))
        elseif rq.status == 401 or rq.status == 403 then
          info.qido = "secured"
          local wa = hget(rq.header, "WWW-Authenticate")
          if wa then info["www-authenticate"] = wa end
        elseif rq.status == 404 then
          info.qido = "not-found"
        elseif rq.status == 429 then
          info.qido = "rate-limited"
          local ra = hget(rq.header, "Retry-After")
          if ra then
            addwarn(("advisory: QIDO-RS rate limited at %s (Retry-After: %s)"):format(b.base, ra))
          else
            addwarn(("advisory: QIDO-RS rate limited at %s"):format(b.base))
          end
        elseif rq.status == 503 then
          info.qido = "unavailable"
        end
        -- omit qido entirely if indeterminate
      end
    end

    -- CORS (skip if OPTIONS 405)
    if do_cors then
      local rc = http_options_cached(host, port, b.base .. "/studies?limit=0", {
        ["Origin"] = "https://example.com",
        ["Access-Control-Request-Method"] = "GET",
      })
      if rc and rc.header and rc.status ~= 405 then
        local acao = hget(rc.header, "Access-Control-Allow-Origin")
        local acc  = hget(rc.header, "Access-Control-Allow-Credentials")
        if (acao and lc(acao) == "*") and (acc and truthy(acc)) then
          info.cors_risky = true
          addwarn(("warning: risky CORS at %s (ACAO: * with credentials=true)"):format(b.base))
        end
      end
    end

    -- STOW (advisory)
    if do_stow then
      local rs = http_options_cached(host, port, b.base .. "/studies", {
        ["Access-Control-Request-Method"] = "POST",
        ["Origin"] = "https://example.com",
      })
      if rs and rs.header then
        local allow = (hget(rs.header, "Allow") or "") .. "," .. (hget(rs.header, "Access-Control-Allow-Methods") or "")
        if lc(allow):find("post", 1, true) and not (rs.status == 401 or rs.status == 403) then
          info.stow_maybe = true
          addwarn(("advisory: STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(b.base .. "/studies"))
        end
      end
    end

    table.insert(out.dicomweb.bases, info)
  end

  -- Broader flavor awareness: WADO-URI presence (safe check)
  do
    local r = http_get_cached(host, port, "/wado")
    if r and (r.status == 200 or r.status == 400 or r.status == 401 or r.status == 403) then
      out.dicomweb.wado_uri = true
    end
  end

  if #warn > 0 then
    out.warnings = warn
  end

  if (next(out.orthanc) == nil) and (next(out.ui) == nil) and (#out.dicomweb.bases == 0) and (#warn == 0) then
    return nil
  end
  return out
end
