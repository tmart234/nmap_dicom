---
-- Detect DICOM-related HTTP endpoints and flag common DICOMweb misconfigurations.
--
-- Finds:
--   - Orthanc REST API (/system) and (best-effort) version
--   - DICOMweb bases (Orthanc: /dicom-web; dcm4chee: /dcm4chee-arc/rs; dcm4chee AET: /dcm4chee-arc/aets/DCM4CHEE/rs)
--   - OHIF viewer
--   - Dicoogle and Kheops proxies
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
-- PORT     STATE SERVICE   REASON  VERSION
-- 8042/tcp open  dicom-web syn-ack Orthanc 1.12.10
-- | dicom-web-info: 
-- |   Orthanc: 1.12.10 (Path: /system)
-- |   Authentication: Basic realm="Orthanc Secure Area"
-- |   
-- |   DICOMweb Endpoints: 
-- |     /dcm4chee-arc/aets/DCM4CHEE/rs (impl: dcm4chee, qido: secured)
-- |     /dcm4chee-arc/rs (impl: dcm4chee, qido: secured)
-- |     /dicom-web (impl: orthanc, qido: secured)
-- |     
-- |   Features: 
-- |     WADO-URI: Enabled
-- |     
-- |   Warnings: 
-- |     [DWI-003] http (no TLS) detected
-- |_    [DWI-002] VULN: Orthanc accepts default credentials (orthanc:orthanc)
--
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"

-- Optional: nselib/vulns.lua (not available in all builds)
local have_vulns, vulns = pcall(require, "vulns")

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
  if not ok then 
    stdnse.debug1("Request failed: %s %s", method, path)
    return nil 
  end
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
  local set = parse_ports_arg(stdnse.get_script_args("dicom-web.ports"))
  if set and set[port.number] then return true end

  if shortport.port_or_service({80, 443, 8042, 3000, 8080, 8443}, {"http","https","http-alt"}, "tcp")(host, port) then
    return true
  end
  
  -- Fallback: explicit ports even if service detection failed or claimed weird service
  -- This fixes the "fs-agent" or "nagios-nsca" issue in CI
  if port.number == 8042 or port.number == 8080 or port.number == 3000 then
     return true
  end
  
  return false
end

-- -------------------- action --------------------

action = function(host, port)
  -- Data collectors (not output tables yet)
  local orthanc_info = nil
  local ui_found = {}
  local endpoints_found = {}
  local features_found = {}
  local global_auth = nil

  -- Safe/optional Nmap 'vulns' integration (no-op if missing)
  local add_vuln = function(_) end
  local vuln_report = nil
  if have_vulns and vulns and vulns.Report and vulns.Report.new and vulns.STATE then
    vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
    if vuln_report and vuln_report.add then
      add_vuln = function(args)
        vuln_report:add{
          title       = args.title,
          state       = args.state or vulns.STATE.VULN,   -- or .LIKELY_VULN / .POTENTIAL
          risk_factor = args.risk or "High",
          description = args.desc,
          references  = args.refs or {},
          IDS         = args.ids  or {},
          extra_info  = args.evidence and ("evidence: " .. args.evidence) or nil,
        }
      end
    end
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
      stdnse.debug1("Orthanc check /system: %s. Body len: %d", r_no.status, #r_no.body)
      -- DEBUG: Show body if we failed to match
      if r_no.status == 200 and not (body_has(r_no.body, '"name"') and body_has(r_no.body, "orthanc")) then
         stdnse.debug1("Orthanc 200 OK but mismatch. Body start: %s", r_no.body:sub(1,200))
      end

      if r_no.status == 200 and r_no.body and (body_has(r_no.body, '"name"') and body_has(r_no.body, "orthanc")) then
        orthanc_seen = true
        orthanc_auth = "no-auth"
        orthanc_version = r_no.body:match('"version"%s*:%s*"([^"]+)"') or
                          r_no.body:match('"Version"%s*:%s*"([^"]+)"')
      elseif r_no.status == 401 or r_no.status == 403 then
        orthanc_seen = true
        orthanc_auth = "auth-required"
        orthanc_wa = hget(r_no.header, "WWW-Authenticate")
        
        -- Default: assume the first WWW-Authenticate we see is the "Global" one for this server
        if not global_auth then global_auth = orthanc_wa end

        -- default creds probe only if Basic is advertised
        local wa_lc = lc(orthanc_wa or "")
        if not no_defs and wa_lc:find("basic", 1, true) then
          local def_auth = make_basic_auth("orthanc","orthanc")
          if def_auth then
            local r_def = http_get_cached(host, port, "/system", { ["Accept"]="application/json", ["Authorization"]=def_auth })
            if r_def and r_def.status == 200 and r_def.body then
              warn_code("DWI-002", "VULN: Orthanc accepts default credentials (orthanc:orthanc)")
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
      orthanc_info = string.format("%s (Path: /system)", orthanc_version or "unknown")
      if orthanc_auth == "no-auth" then
        adv_code("DWI-006", "Orthanc /system reachable without authentication")
      end
    end
  end

  -- -------- General UI / Server Header detection --------
  -- Checks for Dicoogle, Kheops, etc via root path
  do
    local r_root = http_get_cached(host, port, "/")
    if r_root and r_root.status then 
       stdnse.debug1("Root check /: %s. Server: %s", r_root.status, hget(r_root.header, "Server") or "nil")
       local srv = lc(hget(r_root.header, "Server") or "")
       local bdy = lc(r_root.body or "")
       local ttl = bdy:match("<title>([^<]+)</title>") or ""
       
       -- Dicoogle Detection
       if srv:find("dicoogle", 1, true) or ttl:find("dicoogle", 1, true) then
          local v = srv:match("dicoogle/([%d%.]+)")
          ui_found["Dicoogle"] = v and ("Version " .. v) or "/"
       end
       
       -- Kheops Detection (Proxy)
       if srv:find("kheops", 1, true) or hget(r_root.header, "X-Kheops-Version") then
          ui_found["Kheops"] = "API Proxy"
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
          ui_found["dcm4chee-arc-ui"] = "/dcm4chee-arc/ui2/"
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
        stdnse.debug1("OHIF check %s: 200. Body len %d", p, #r.body)
        -- IMPROVED: Check for title tag as well
        local b = lc(r.body)
        if body_has(r.body, "data-cy-root") or body_has(r.body, "ohif") or body_has(r.body, "app-config.js") or b:find("<title>ohif", 1, true) then
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
      -- Best-effort OHIF version from app-config.js (no warning if missing)
      local rjs = http_get_cached(host, port, (mount or "/") .. "app-config.js")
      local ver_str = ""
      if rjs and rjs.status == 200 and rjs.body and #rjs.body > 0 then
        local body = rjs.body
        local v =
          body:match("appVersion[%s%:%=]['\"]([^'\"]+)['\"]") or
          body:match("window%.config%s*=%s*{.-appVersion%s*:%s*['\"]([^'\"]+)['\"]") or
          body:match("process%.env%.APP_VERSION%s*=%s*['\"]([^'\"]+)['\"]")
        if v then ver_str = " (Version: " .. v .. ")" end
      end
      ui_found["OHIF Viewer"] = (mount or "/") .. ver_str
    end
  end

  -- -------- DICOMweb checks --------
  local bases = {
    {impl="orthanc",   base="/dicom-web"},
    {impl="dcm4chee",  base="/dcm4chee-arc/rs"},
    {impl="dcm4chee",  base="/dcm4chee-arc/aets/DCM4CHEE/rs"}, -- common AET route; ok if 404
    {impl="dicoogle",  base="/dicom-web"}, 
    {impl="kheops",    base="/api"},  
  }
  table.sort(bases, function(a,b) return a.base < b.base end)

  local function is_dicom_json(r)
    if not (r and r.status == 200 and r.body) then return false end
    local ct = lc(hget(r.header, "Content-Type") or "")
    if ct:find("application/dicom%+json", 1, false) then return true end
    -- Check for keys if header is missing/wrong
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
    local r = http_get_cached(host, port, b.base .. "/")
    if r and (r.status == 200 or r.status == 204 or r.status == 401 or r.status == 403) then
      
      -- Found a valid base!
      local qido_status = "unknown"
      local local_wa = hget(r.header, "WWW-Authenticate")
      if not global_auth and local_wa then global_auth = local_wa end

      if do_qido then
        local rq, used_path = qido_try_paths(b.base)
        if rq then
          if is_dicom_json(rq) then
            qido_status = "open"
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
            qido_status = "secured"
            local w = hget(rq.header, "WWW-Authenticate")
            if w then local_wa = w end
          elseif rq.status == 404 then
            qido_status = "not-found"
          elseif rq.status == 429 then
            qido_status = "rate-limited"
          elseif rq.status == 503 then
            qido_status = "unavailable"
          else
            -- DEBUG: Why did QIDO check fail?
            stdnse.debug1("QIDO %s check failed. Status: %s. CT: %s. Body start: %s", 
               b.base, rq.status, hget(rq.header,"Content-Type") or "nil", rq.body:sub(1,100))
          end
        end
      end

      -- Clean string generation for output
      local extra = ""
      if local_wa and local_wa ~= global_auth then
         extra = " (Auth: " .. local_wa .. ")"
      end
      local entry = string.format("%s (impl: %s, qido: %s)%s", b.base, b.impl, qido_status, extra)
      table.insert(endpoints_found, entry)

      if do_cors then
        local rc = http_options_cached(host, port, b.base .. "/studies?limit=0", {
          ["Origin"] = "https://example.com",
          ["Access-Control-Request-Method"] = "GET",
        })
        if rc and rc.header and rc.status ~= 405 then
          local acao = hget(rc.header, "Access-Control-Allow-Origin")
          local acc  = hget(rc.header, "Access-Control-Allow-Credentials")
          if (acao and lc(acao) == "*") and (acc and truthy(acc)) then
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
            adv_code("DWI-009", ("STOW-RS may allow POST (unauthenticated?) at %s (via OPTIONS)"):format(b.base .. "/studies"))
          end
        end
      end
    end
  end

  -- WADO-URI presence (safe check)
  do
    local r = http_get_cached(host, port, "/wado")
    if r and (r.status == 200 or r.status == 400 or r.status == 401 or r.status == 403) then
      features_found["WADO-URI"] = "Enabled"
    end
  end

  -- Build final output
  local out = stdnse.output_table()
  
  if orthanc_info then out["Orthanc"] = orthanc_info end
  
  if global_auth then out["Authentication"] = global_auth end
  
  if next(ui_found) then out["Web Interfaces"] = ui_found end
  
  if #endpoints_found > 0 then out["DICOMweb Endpoints"] = endpoints_found end
  
  if next(features_found) then out["Features"] = features_found end

  if #warn > 0 then
    out.warnings = warn
  end

  if vuln_report and vuln_report.make_output then
    local vuln_out = vuln_report:make_output()
    if vuln_out then
      out.vulnerabilities = vuln_out
    end
  end

  if next(out) == nil then return nil end

  -- SERVICE DETECTION FIX
  -- If we found Orthanc, UI, or specific endpoints, we know this is DICOMweb
  if orthanc_seen or #endpoints_found > 0 or next(ui_found) then
     port.version.name = "dicom-web"
     
     if orthanc_seen then
        port.version.product = "Orthanc"
        if orthanc_version then port.version.version = orthanc_version end
        
     elseif ui_found["Dicoogle"] then
        port.version.product = "Dicoogle"
        
     elseif ui_found["Kheops"] then
        port.version.product = "Kheops Proxy"
        
     elseif ui_found["OHIF Viewer"] then
        port.version.product = "OHIF Viewer"
        -- Try to extract version from the string "Path/ (Version: 1.2.3)"
        local v_str = ui_found["OHIF Viewer"]
        local v_match = v_str:match("Version: ([%d%.]+)")
        if v_match then port.version.version = v_match end

     elseif #endpoints_found > 0 then
        -- We found valid QIDO endpoints (e.g. /studies), but no specific vendor signature
        port.version.product = "Standard DICOMweb"
     end
     
     nmap.set_port_version(host, port)
  end

  return out
end