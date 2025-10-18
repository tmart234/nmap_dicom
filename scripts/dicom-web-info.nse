---
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) and (best-effort) version
--   - DICOMweb bases (Orthanc: /dicom-web; dcm4chee: /dcm4chee-arc/rs; dcm4chee AET: /dcm4chee-arc/aets/DCM4CHEE/rs)
--   - OHIF viewer
--
-- Security checks (non-intrusive):
--   - http instead of https (suppressed if cleanly upgraded to same-host https)  [advisory]
--   - Unauthenticated QIDO-RS listing (/studies?limit=1) with DICOM JSON         [vuln]
--     (tries Accept: application/dicom+json, then falls back to application/json on 406)
--   - risky CORS (ACAO: * with credentials=true)                                 [advisory]
--   - (advisory) STOW-RS appears allowed via OPTIONS without auth
--   - (advisory) missing Content-Security-Policy on known UIs
--   - (info) WWW-Authenticate scheme on 401 (e.g., Basic/Bearer)
--   - (vuln) Orthanc default creds accepted (orthanc:orthanc); disable with dicom-web.no-defaults=true
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
-- |     warning [DWI-003]: http (no TLS) detected
-- |_    advisory [DWI-005]: OHIF root missing Content-Security-Policy
--
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"
local vulns     = require "vulns"

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

local function header_fingerprint(hdr)
  if not hdr then return "" end
  -- Normalize and only keep headers we vary on
  local wanted = {
    "accept",
    "authorization",
    "origin",
    "access-control-request-method",
  }
  local t = {}
  local map = {}
  for k, v in pairs(hdr) do
    map[string.lower(k)] = v
  end
  for _, k in ipairs(wanted) do
    local v = map[k]
    if v then table.insert(t, k .. "=" .. tostring(v)) end
  end
  table.sort(t)
  return table.concat(t, "&")
end

local function cache_key(method, path, hdr)
  return method .. "|" .. path .. "|" .. header_fingerprint(hdr)
end

local function http_get_cached(host, port, path, hdr)
  -- Do NOT cache auth’d requests
  local h = hdr or {}
  if h["Authorization"] or h["authorization"] then
    return http_get(host, port, path, hdr)
  end
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

  -- Nmap 'vulns' integration (initialized inside action for host/port)
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local function add_vuln(args)
    local v = {
      title       = args.title,
      state       = args.state or vulns.STATE.VULN,
      risk_factor = args.risk or "High",
      description = args.desc,
      references  = args.refs or {},
      IDS         = args.ids  or {},
      extra_info  = args.evidence and ("evidence: " .. args.evidence) or nil,
    }
    vuln_report:add(v)
  end

  -- stable, pretty warnings with short codes (non-vuln)
  local warn = stdnse.output_table()
  local function addwarn(s) table.insert(warn, s) end
  local function warn_code(code, msg) addwarn(("warning [%s]: %s"):format(code, msg)) end
  local function adv_code(code, msg)  addwarn(("advisory [%s]: %s"):format(code, msg)) end

  -- toggles
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
    if not (r and (r.status == 301 or r.status == 302 or r.status == 307 or r.status == 308)) then
      return false
    end
    local loc = hget(r.header, "Location")
    if not loc then return false end
    local scheme, hostpart = loc:match("^(https?)://([^/]+)")
    if scheme ~= "https" then return false end
    return (hostpart == host.targetname or hostpart == host.ip)
  end

  -- TLS (advisory only)
  if port.tunnel ~= "ssl" then
    if not is_https_redirect() then
      warn_code("DWI-003", "http (no TLS) detected")
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
              warn_code("DWI-002", "Orthanc accepts default credentials (orthanc:orthanc)")
              -- Report as a true vuln
              add_vuln{
                title = "Orthanc default credentials accepted (orthanc:orthanc)",
                risk  = "High",
                desc  = "The Orthanc REST API accepted factory default credentials.",
                refs  = { "Orthanc Security Recommendations" },
                ids   = { CWE = "CWE-521" },
                evidence = "GET /system → 200 with Basic auth (redacted)",
              }
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
        adv_code("DWI-006", "Orthanc /system reachable without authentication")
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
            adv_code("DWI-007", "DCM4CHEE UI missing Content-Security-Policy")
          end
          break
        end
      end
    end
  end

  -- -------- OHIF detection + version (best-effort) --------
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
            adv_code("DWI-005", "OHIF root missing Content-Security-Policy")
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
      -- Best-effort OHIF version from app-config.js (no warning if missing)
      local rjs = http_get_cached(host, port, (mount or "/") .. "app-config.js")
      if rjs and rjs.status == 200 and rjs.body and #rjs.body > 0 then
        local body = rjs.body
        local v =
          body:match("appVersion[%s%:%=]['\"]([^'\"]+)['\"]") or
          body:match("window%.config%s*=%s*{.-appVersion%s*:%s*['\"]([^'\"]+)['\"]") or
          body:match("process%.env%.APP_VERSION%s*=%s*['\"]([^'\"]+)['\"]")
        if v then
          out.ui["ohif_version"] = v
        end
      end
    end
  end

  -- -------- DICOMweb checks --------
  local bases = {
    {impl="orthanc",   base="/dicom-web"},
    {impl="dcm4chee",  base="/dcm4chee-arc/rs"},
    {impl="dcm4chee",  base="/dcm4chee-arc/aets/DCM4CHEE/rs"}, -- common AET route; ok if 404
  }
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
    local info = stdnse.output_table()
    info.base = b.base
    info.impl = b.impl

    local r = http_get_cached(host, port, b.base .. "/")
    if r and (r.status == 200 or r.status == 204 or r.status == 401 or r.status == 403) then
      info.reachable = true
      if b.base == "/dicom-web" and r.status == 200 then
        info["orthanc-plugin-enabled"] = true
      end
    end

    if do_qido then
      local rq, used_path = qido_try_paths(b.base)
      if rq then
        if is_dicom_json(rq) then
          info.qido = "open"
          -- True vulnerability: unauthenticated QIDO returns DICOM JSON
          add_vuln{
            title = "DICOMweb QIDO-RS accessible without authentication",
            risk  = "High",
            desc  = "QIDO-RS returns study/series/instance metadata without authentication.",
            refs  = { "DICOM PS3.18 Web Services – QIDO-RS security" },
            ids   = { CWE = "CWE-200" },
            evidence = ("GET %s → %s, %s"):format(used_path, rq.status, hget(rq.header,"Content-Type") or "no CT"),
          }
          warn_code("DWI-001", ("unauthenticated QIDO-RS listing at %s (GET %s)"):format(b.base, used_path))
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
            adv_code("DWI-008", ("QIDO-RS rate limited at %s (Retry-After: %s)"):format(b.base, ra))
          else
            adv_code("DWI-008", ("QIDO-RS rate limited at %s"):format(b.base))
          end
        elseif rq.status == 503 then
          info.qido = "unavailable"
        end
      end
    end

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
          -- advisory only (not a vuln record)
          warn_code("DWI-004", ("risky CORS at %s (ACAO: * with credentials=true)"):format(b.base))
        end
      end
    end

    if do_stow then
      local rs = http_options_cached(host, port, b.base .. "/studies", {
        ["Access-Control-Request-Method"] = "POST",
        ["Origin"] = "https://example.com",
      })
      if rs and rs.header then
        local allow = (hget(rs.header, "Allow") or "") .. "," .. (hget(rs.header, "Access-Control-Allow-Methods") or "")
        if lc(allow):find("post", 1, true) and not (rs.status == 401 or rs.status == 403) then
          info.stow_maybe = true
          adv_code("DWI-009", ("STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(b.base .. "/studies"))
        end
      end
    end

    table.insert(out.dicomweb.bases, info)
  end

  -- WADO-URI presence (safe check)
  do
    local r = http_get_cached(host, port, "/wado")
    if r and (r.status == 200 or r.status == 400 or r.status == 401 or r.status == 403) then
      out.dicomweb.wado_uri = true
    end
  end

  if #warn > 0 then
    out.warnings = warn
  end

  local vuln_out = vuln_report:make_output()
  if vuln_out then
    out.vulnerabilities = vuln_out
  end

  if (next(out.orthanc) == nil) and (next(out.ui) == nil) and (#out.dicomweb.bases == 0) and (#warn == 0) and (not vuln_out) then
    return nil
  end
  return out
end
