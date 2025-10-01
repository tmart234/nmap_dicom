-- dicom-web-info.nse
--[[
Detects DICOM-related HTTP endpoints:
 - Orthanc REST API (/system) and extracts version if readable
 - OHIF Viewer (static frontend)
 - dcm4chee-arc UI2 (admin console)

@usage
nmap -p 8042,3000,8080 --script dicom-web-info <target>
nmap --script dicom-web-info --script-args dicom-web.ports=8042,3000,8080,dicom-web.orthanc.user=foo,dicom-web.orthanc.pass=bar <target>

@args dicom-web.ports            Comma-separated list of ports to test (optional)
@args dicom-web.orthanc.user     Basic auth user for Orthanc (optional)
@args dicom-web.orthanc.pass     Basic auth pass for Orthanc (optional)

@output
| dicom-web-info:
|   Orthanc REST API: /system (version 1.12.9)
|   DCM4CHEE Archive UI: /dcm4chee-arc/ui2/ (authentication required)
|_  OHIF Viewer: detected at /
]] author = "Tyler M"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local base64 = require "base64"
local string = require "string"
local json = require "json"

local function parse_ports_arg(s)
    if not s then
        return nil
    end
    local t = {}
    for p in string.gmatch(s, "%d+") do
        t[tonumber(p)] = true
    end
    return next(t) and t or nil
end

portrule = function(host, port)
    if not (port.protocol == "tcp" and port.state == "open") then
        return false
    end
    local arg = stdnse.get_script_args("dicom-web.ports")
    local set = parse_ports_arg(arg)
    if set and set[port.number] then
        return true
    end
    return shortport.port_or_service({80, 443, 8042, 3000, 8080}, {"http", "https"}, "tcp")(host, port)
end

action = function(host, port)
    local results = {}

    -- Common opts; enable TLS if needed
    local use_ssl = shortport.ssl(host, port)
    local opts = {
        timeout = 5000,
        header = {
            ["Accept"] = "application/json, */*"
        },
        ssl = use_ssl
    }

    -- Orthanc /system
    do
        local path = "/system"
        local user = stdnse.get_script_args("dicom-web.orthanc.user")
        local pass = stdnse.get_script_args("dicom-web.orthanc.pass")
        local o = {
            timeout = 5000,
            ssl = use_ssl,
            header = {
                ["Accept"] = "application/json"
            }
        }
        if user and pass then
            o.header["Authorization"] = "Basic " .. base64.encode(user .. ":" .. pass)
        end
        local ok, resp = pcall(http.get, host, port, path, o)
        if ok and resp and resp.status then
            if resp.status == 200 and resp.body then
                local ct = resp.header and (resp.header["Content-Type"] or resp.header["content-type"]) or ""
                local is_json = ct:lower():find("application/json", 1, true) ~= nil
                local ver
                if is_json then
                    local okj, j = pcall(json.parse, resp.body)
                    if okj and type(j) == "table" and j["Version"] then
                        ver = tostring(j["Version"])
                    end
                end
                if ver then
                    table.insert(results, string.format("Orthanc REST API: %s (version %s)", path, ver))
                end
            elseif resp.status == 401 or resp.status == 403 then
                table.insert(results, string.format("Orthanc REST API: %s (authentication required)", path))
            end
        end
    end

    -- dcm4chee-arc UI2
    do
        local candidates = {"/dcm4chee-arc/ui2/", "/dcm4chee-arc/ui2/index.html"}
        for _, p in ipairs(candidates) do
            local ok, resp = pcall(http.get, host, port, p, {
                timeout = 5000,
                ssl = use_ssl
            })
            if ok and resp and resp.status then
                if resp.status == 200 then
                    table.insert(results, string.format("DCM4CHEE Archive UI: %s", p))
                    break
                elseif resp.status == 302 or resp.status == 401 or resp.status == 403 then
                    table.insert(results, string.format("DCM4CHEE Archive UI: %s (authentication required)", p))
                    break
                end
            end
        end
    end

    -- OHIF Viewer
    do
        local ok, resp = pcall(http.get, host, port, "/", {
            timeout = 5000,
            ssl = use_ssl
        })
        if ok and resp and resp.status == 200 and resp.body then
            if resp.body:find("app%-config%.js", 1, true) or resp.body:find("OHIF", 1, true) or
                (resp.header and ((resp.header["X-Powered-By"] or ""):lower():find("ohif", 1, true) ~= nil)) then
                table.insert(results, "OHIF Viewer: detected at /")
            end
        end
    end

    if #results == 0 then
        return nil
    end

    local out = stdnse.output_table()
    for _, line in ipairs(results) do
        table.insert(out, line)
    end
    return out
end
