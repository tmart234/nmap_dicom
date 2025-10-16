-- dicom-web-info.nse
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) + (best-effort) version
--   - DICOMweb bases (Orthanc: /dicom-web, dcm4chee: /dcm4chee-arc/rs, dcm4chee AE-scoped: /dcm4chee-arc/aets/<AET>/rs)
--   - OHIF viewer
--
-- Security checks (non-intrusive):
--   - HTTP used instead of HTTPS
--   - Unauthenticated QIDO-RS listing (/studies?limit=1) with DICOM JSON (tries application/dicom+json, then application/json on 406)
--   - Risky CORS (ACAO: * with credentials=true)
--   - (Advisory) STOW-RS appears allowed via OPTIONS without auth
--   - (Opt-in) Orthanc default creds accepted (orthanc:orthanc)
--   - (Advisory) Missing Content-Security-Policy on UIs
--   - (Info) Advertised auth scheme via WWW-Authenticate (e.g., Basic/Bearer) on 401
--
-- Script args (all optional):
--   dicom-web.qido-test=true|false          (default true)
--   dicom-web.cors-test=true|false          (default true)
--   dicom-web.stow-test=true|false          (default false)
--   dicom-web.try-defaults=true|false       (default false)
--   dicom-web.orthanc.user=<user>           (default none)
--   dicom-web.orthanc.pass=<pass>           (default none)
--   dicom-web.ports=8042,3000,8080          (limit portrule)
--   dicom-web.extra-bases=/pacs/dicom-web,/pacs/rs   (comma-separated extra base paths)
--   dicom-web.aet=DCM4CHEE                  (AE title to try for dcm4chee AE-scoped base)
--   dicom-web.legacy-lines=true|false       (default true; emit classic human-readable lines for CI greps)
--
-- Examples:
--   nmap -p 8042,3000 --script dicom-web-info localhost
--   nmap -p 8042 --script dicom-web-info --script-args dicom-web.try-defaults=true localhost
--   nmap -p 8081 --script dicom-web-info --script-args dicom-web.extra-bases=/pacs/dicom-web,/pacs/rs localhost
--
-- Note: This script is "safe": it only performs GET and OPTIONS requests and never uploads DICOM objects.
--
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}  -- removed "vuln" (misconfigs, not CVEs)

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

local function split_csv_paths(s)
  if not s or s == "" then return {} end
  local out = {}
  for p in string.gmatch(s, "[^,%s]+") do
    if p:sub(1,1) ~= "/" then p = "/" .. p end
    -- trim trailing slashes (except root)
    if #p > 1 and p:sub(-1) == "/" then p = p:sub(1, -2) end
    table.insert(out, p)
  end
  return out
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

-- Build Authorization: Basic ... (avoid undeclared globals)
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
      -- simple same-host absolute-path follow; ignore external hosts
      if loc:sub(1,1) == "/" then
        return _generic(host, port, "GET", loc, hdr)
      end
      -- best-effort: if absolute URL to same host, extract path
      local scheme, hostpart, path = loc:match("^(https?)://([^/]+)(/.*)$")
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
  local warn  = {}

  -- toggles
  local do_qido  = truthy(stdnse.get_script_args("dicom-web.qido-test") or "true")
  local do_cors  = truthy(stdnse.get_script_args("dicom-web.cors-test") or "true")
  local do_stow  = truthy(stdnse.get_script_args("dicom-web.stow-test") or "false")
  local try_defs = truthy(stdnse.get_script_args("dicom-web.try-defaults") or "false")

  -- extras
  local extra_bases = split_csv_paths(stdnse.get_script_args("dicom-web.extra-bases"))
  local aet = stdnse.get_script_args("dicom-web.aet") or "DCM4CHEE"

  -- structure result keys for CI-friendliness
  out.orthanc  = {}
  out.ui       = {}
  out.dicomweb = { bases = {} }

  -- legacy single-line outputs for CI greps (default: true)
  local legacy_lines = true
  local arg_legacy = stdnse.get_script_args("dicom-web.legacy-lines")
  if arg_legacy ~= nil then legacy_lines = truthy(arg_legacy) end

  -- TLS/HTTP hint
  local is_tls = (port.tunnel == "ssl")
  if not is_tls then
    table.insert(warn, "Warning: HTTP (no TLS) detected")
  end

  -- -------- Orthanc detection --------
  local orthanc_seen, orthanc_auth, orthanc_version = false, "unknown", nil
  local orthanc_auth_schemes = {}
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
        -- collect advertised auth scheme(s)
        local wa = hget(r_no.header, "WWW-Authenticate")
        if wa then table.insert(orthanc_auth_schemes, wa) end
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
      out.orthanc.path    = "/system"
      out.orthanc.version = orthanc_version or "unknown"
      out.orthanc.auth    = orthanc_auth
      if #orthanc_auth_schemes > 0 then
        out.orthanc["www-authenticate"] = orthanc_auth_schemes
      end
      if orthanc_auth == "no-auth" then
        table.insert(warn, "Insecure: Orthanc /system reachable without authentication")
      end
      if legacy_lines then
        local v = out.orthanc.version or "unknown"
        table.insert(out, ("Orthanc REST API: /system (version %s)"):format(v))
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
          out.ui["dcm4chee-arc-ui"] = "/dcm4chee-arc/ui2/"
          -- CSP advisory
          local csp = hget(r.header, "Content-Security-Policy")
          if not csp then
            table.insert(warn, "Advisory: DCM4CHEE UI missing Content-Security-Policy")
          end
          break
        end
      end
    end
  end

  -- -------- OHIF detection (tightened) --------
  do
    local ohif = false
    local r = http_get(host, port, "/")
    if r and r.status == 200 and r.body then
      if body_has(r.body, "data-cy-root") or body_has(r.body, "ohif") or body_has(r.body, "app-config.js") then
        ohif = true
      end
      local csp = hget(r.header, "Content-Security-Policy")
      if ohif and not csp then
        table.insert(warn, "Advisory: OHIF root missing Content-Security-Policy")
      end
    end
    if not ohif then
      local r2 = http_get(host, port, "/app-config.js")
      if r2 and r2.status == 200 and r2.body and #r2.body > 0 then
        if body_has(r2.body, "window.config") or body_has(r2.body, "getAppConfig") then
          ohif = true
        end
      end
    end
    if ohif then
      out.ui["ohif"] = "/"
      if legacy_lines then
        table.insert(out, "OHIF Viewer: detected at /")
      end
    end
  end

  -- -------- DICOMweb checks --------
  local bases = {
    {name="Orthanc DICOMweb", base="/dicom-web"},
    {name="dcm4chee DICOMweb", base="/dcm4chee-arc/rs"},
    {name="dcm4chee DICOMweb (AET)", base=("/dcm4chee-arc/aets/" .. aet .. "/rs")},
  }

  -- merge user-specified extra bases
  for _, p in ipairs(extra_bases) do
    table.insert(bases, { name="Custom DICOMweb", base=p })
  end

  local function is_dicom_json(r)
    if not (r and r.status == 200 and r.body) then return false end
    local ct = lc(hget(r.header, "Content-Type") or "")
    if ct:find("application/dicom%+json", 1, false) then return true end
    -- heuristic tags commonly present in DICOM JSON
    return body_has(r.body, '"StudyInstanceUID"')
        or body_has(r.body, '"SeriesInstanceUID"')
        or body_has(r.body, '"SOPInstanceUID"')
        or body_has(r.body, '"MainDicomTags"')
  end

  local function qido_try(host, port, path)
    -- try dicom+json, then json on 406
    local r = http_get(host, port, path, { ["Accept"]="application/dicom+json" })
    if r and r.status == 406 then
      r = http_get(host, port, path, { ["Accept"]="application/json" })
    end
    return r
  end

  -- Track discovered bases and per-base findings
  for _, b in ipairs(bases) do
    local base_info = { name=b.name, base=b.base }
    -- Base reachability (and Orthanc plugin "enabled" index page is often HTML/200)
    do
      local r = http_get(host, port, b.base .. "/")
      if r and (r.status == 200 or r.status == 401 or r.status == 403) then
        base_info.reachable = true
        -- A small nicety for Orthanc: if HTML index is returned on /dicom-web/, mark plugin-enabled
        if b.base == "/dicom-web" and r.status == 200 then
          base_info["orthanc-plugin-enabled"] = true
        end
      end
    end

    -- QIDO listing probe
    if do_qido then
      local path = b.base .. "/studies?limit=1"
      local r = qido_try(host, port, path)
      if r then
        if is_dicom_json(r) then
          base_info.qido_open = true
          table.insert(warn, ("Insecure: Unauthenticated QIDO-RS listing at %s (GET %s)"):format(b.name, path))
        elseif r.status == 401 or r.status == 403 then
          base_info.qido_secured = true
          -- record auth scheme if available
          local wa = hget(r.header, "WWW-Authenticate")
          if wa then base_info["www-authenticate"] = wa end
        elseif r.status == 404 then
          base_info.qido_not_found = true
        end
      end
    end

    -- CORS preflight on GET
    if do_cors then
      local path = b.base .. "/studies?limit=0"
      local r = http_options(host, port, path, {
        ["Origin"] = "https://example.com",
        ["Access-Control-Request-Method"] = "GET",
      })
      -- if OPTIONS not supported (405), skip CORS evaluation
      if r and r.header and r.status ~= 405 then
        local acao = hget(r.header, "Access-Control-Allow-Origin")
        local acc  = hget(r.header, "Access-Control-Allow-Credentials")
        if (acao and lc(acao) == "*") and (acc and truthy(acc)) then
          base_info.cors_risky = true
          table.insert(warn, ("Warning: Risky CORS at %s (ACAO: * with credentials=true)"):format(b.base))
        end
      end
    end

    -- STOW advisory via OPTIONS
    if do_stow then
      local path = b.base .. "/studies"
      local r = http_options(host, port, path, {
        ["Access-Control-Request-Method"] = "POST",
        ["Origin"] = "https://example.com",
      })
      if r and r.header then
        local allow = (hget(r.header, "Allow") or "") .. "," .. (hget(r.header, "Access-Control-Allow-Methods") or "")
        if lc(allow):find("post", 1, true) and not (r.status == 401 or r.status == 403) then
          base_info.stow_maybe_allowed = true
          table.insert(warn, ("Advisory: STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(path))
        end
      end
    end

    table.insert(out.dicomweb.bases, base_info)
  end

  -- place warnings last
  out.warnings = warn

  -- Nmap pretty-prints nested tables; return nil if truly nothing interesting
  if (next(out.orthanc) == nil) and (next(out.ui) == nil) and (#out.dicomweb.bases == 0) and (#warn == 0) then
    return nil
  end
  return out
end
