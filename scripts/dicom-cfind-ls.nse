description = [[
Lists DICOM objects stored on a PACS server using C-FIND queries at the
PATIENT, STUDY, SERIES, and IMAGE levels. Results are displayed hierarchically
showing patients, studies, series and (optionally) individual instances,
including any private tags (PS3.5 section 7.8) returned by the SCP.

The script negotiates an A-ASSOCIATE with the Study Root (or Patient Root)
Query/Retrieve Information Model - FIND SOP Class and reuses the association
across query levels while holding the per-host DICOM association mutex so
production PACS association pools are not exhausted. Transient congestion
rejects are retried with exponential backoff, C-CANCEL-RQ is issued cleanly
when max_results is reached, and A-ABORT is sent on error/timeout paths so
the SCP frees the slot immediately.

It can also retrieve (download) individual DICOM instances using C-GET when
the --script-args dicom-cfind-ls.save option is set.

NOTE: Many PACS servers accept C-FIND from any associated SCU with no
authentication. If the server returns results, it means patient data
is exposed to any host that can reach the DICOM port -- a critical
finding for security assessments.
]]

---
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls <target>
--
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.called_ae=ORTHANC,dicom-cfind-ls.calling_ae=LAUNCHER' <target>
--
-- @usage
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.level=SERIES,dicom-cfind-ls.max_results=50' <target>
--
-- @usage  (query common or custom private tags)
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.private_tags=00091001:LO;00291010:OB' <target>
--
-- @usage  (download all matching instances to disk)
-- nmap -p 4242 --script dicom-cfind-ls \
--   --script-args 'dicom-cfind-ls.save=/tmp/dicom-dump' <target>
--
-- @args dicom-cfind-ls.called_ae     Target AE Title (default: dicom.called_aet or "ANY-SCP")
-- @args dicom-cfind-ls.calling_ae    Our AE Title (default: dicom.calling_aet or "FINDSCU")
-- @args dicom-cfind-ls.level         Deepest query level: PATIENT, STUDY,
--                                    SERIES, IMAGE (default: "IMAGE")
-- @args dicom-cfind-ls.max_results   Maximum results per level (default: 100)
-- @args dicom-cfind-ls.timeout       Response timeout in seconds (default: 10)
-- @args dicom-cfind-ls.max_pdu       Max PDU Length in bytes (default: 16384)
-- @args dicom-cfind-ls.patient_name  Filter by PatientName (wildcard *
--                                    allowed, default: "*")
-- @args dicom-cfind-ls.patient_id    Filter by PatientID (default: all)
-- @args dicom-cfind-ls.study_date    Filter by StudyDate (YYYYMMDD or range,
--                                    default: all)
-- @args dicom-cfind-ls.modality      Filter by Modality (CT, MR, etc.,
--                                    default: all)
-- @args dicom-cfind-ls.private_tags  Query private tags (PS3.5 section 7.8):
--                                    "true"/"all" probes common vendor
--                                    Private Creator blocks (0009, 0011, 0019,
--                                    0021, 0025, 0029, 0043, 7005); or pass a
--                                    semicolon-separated tag spec list such as
--                                    "00091001:LO;00291010:OB" (accepts
--                                    GGGGEEEE, GGGG.EEEE, or quoted GGGG,EEEE;
--                                    auto-reserves the Private Creator tag).
-- @args dicom-cfind-ls.save          Directory to save DICOM files via C-GET
--                                    (default: disabled)
-- @args dicom-cfind-ls.info_model    Q/R Information Model: "study" or
--                                    "patient" (default: "study", auto-falls
--                                    back to "patient" if Study Root is not
--                                    supported)
-- @args dicom-cfind-ls.full          Include extended return-key tags in
--                                    queries (StudyDate, AccessionNumber,
--                                    ModalitiesInStudy, etc.). Some PACS
--                                    servers abort on unsupported tags; when
--                                    set the script auto-retries with minimal
--                                    tags on A-ABORT. Default: false
-- @args dicom-cfind-ls.ports         Optional comma-separated list of extra
--                                    ports to probe (e.g. "11114,11115").
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-cfind-ls:
-- |   DICOM Q/R Results: (Study Root, FIND)
-- |   Patients: 2
-- |   Studies: 3
-- |   Series: 4
-- |   Instances: 47
-- |   Listing:
-- |     [Patient] John Doe (ID: PATIENT001)
-- |       [Study] 20250115 - CT Abdomen (CT) 1.2.3.4.5.1
-- |         [Series] #1 CT (30 images) 1.2.3.4.5.1.1
-- |       [Study] 20250320 - MR Brain (MR) 1.2.3.4.5.2
-- |         [Series] #1 MR (15 images) 1.2.3.4.5.2.1
-- |     [Patient] Jane Smith (ID: PATIENT002)
-- |       [Study] 20250210 - CR Chest (CR) 1.2.3.4.5.3
-- |         [Series] #1 CR (2 images) 1.2.3.4.5.3.1
-- |   WARNING: Patient data accessible without authentication
-- |_  Saved: 47 instances to /tmp/dicom-dump
--
-- @xmloutput
-- <elem key="DICOM Q/R Results">(Study Root, FIND)</elem>
-- <elem key="Patients">2</elem>
-- <elem key="Studies">3</elem>
-- <elem key="Series">4</elem>
-- <elem key="Instances">47</elem>
-- <table key="Listing">
--   <elem>[Patient] John Doe (ID: PATIENT001)</elem>
--   <elem>  [Study] 20250115 - CT Abdomen (CT) 1.2.3.4.5.1</elem>
--   <elem>    [Series] #1 CT (30 images) 1.2.3.4.5.1.1</elem>
-- </table>
-- <elem key="WARNING">Patient data accessible without authentication</elem>
--
-- @see dicom-info.nse
-- @see dicom-ping.nse
-- @see dicom-brute.nse
---

author = {
  "Paulino Calderon <paulino()calderonpale.com>",
  "Tyler M <tmart234()gmail.com>",
}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local dicom     = require "dicom"
local lfs       = require "lfs"
local math      = require "math"
local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

local COMMON_DICOM_PORTS = {104, 2345, 2761, 2762, 4242, 11112}
local VALID_LEVELS = { PATIENT = true, STUDY = true, SERIES = true, IMAGE = true }
local MAX_CANCEL_DRAIN = 64

local function parse_ports_arg(s)
  if not s then return nil end
  local set = {}
  if type(s) == "table" then
    for _, v in pairs(s) do
      local n = tonumber(v)
      if n then set[n] = true end
    end
  else
    for n in string.gmatch(tostring(s), "%d+") do
      set[tonumber(n)] = true
    end
  end
  return next(set) and set or nil
end

local custom_ports = parse_ports_arg(stdnse.get_script_args("dicom-cfind-ls.ports"))
local default_portrule = shortport.port_or_service(
  COMMON_DICOM_PORTS, {"dicom", "dicom-tls"}, "tcp", "open")

portrule = function(host, port)
  if not (port.protocol == "tcp" and port.state == "open") then return false end
  if custom_ports and custom_ports[port.number] then return true end
  return default_portrule(host, port)
end

-----------------------------------------------------------------------
-- HELPERS
-----------------------------------------------------------------------

local function get_arg(key, default)
  local v = stdnse.get_script_args("dicom-cfind-ls." .. key)
  if v == nil then return default end
  return v
end

local function first_nonempty(...)
  for i = 1, select("#", ...) do
    local v = select(i, ...)
    if v and v ~= "" then return v end
  end
  return ""
end

local function effective_max_pdu(server_max_pdu, client_max_pdu)
  -- Per PS3.8 Annex D.1.1, a server max_pdu of 0 means unlimited.
  if server_max_pdu and server_max_pdu > 0 then
    return math.min(server_max_pdu, client_max_pdu)
  end
  return client_max_pdu
end

-- Create a directory path recursively using lfs.mkdir (no shell invocation).
local function mkdir_p(path)
  if not path or path == "" then return end
  local sep = path:find("\\", 1, true) and "\\" or "/"
  local acc = ""
  if path:sub(1, 1) == "/" then acc = "/" end
  for part in path:gmatch("[^/\\]+") do
    if acc == "" then
      acc = part
    elseif acc == "/" then
      acc = "/" .. part
    else
      acc = acc .. sep .. part
    end
    if not acc:match("^[A-Za-z]:$") then
      lfs.mkdir(acc)
    end
  end
end

-- Check whether a do_associate() error string represents a transient PACS
-- association-pool busy reject (source=3, reason=1 temporary-congestion or
-- reason=2 local-limit-exceeded per PS3.8 Table 9-21).
local function is_busy_reject_str(err)
  if type(err) ~= "string" then return false end
  local src, rsn = err:match("^REJECT%(result=%d+,source=(%d+),reason=(%d+)%)$")
  return src == "3" and (rsn == "1" or rsn == "2")
end

local function associate_with_backoff(host, port, called_ae, calling_ae,
                                      sop_classes, max_pdu, timeout_s,
                                      transfer_uids, roles, tls)
  local retries = math.max(0, math.floor(
      tonumber(stdnse.get_script_args("dicom.retries")) or 2))
  local backoff = math.max(0, tonumber(stdnse.get_script_args("dicom.backoff_ms"))
      or 2000)
  local ok, sock, pctxs, server_max_pdu, elapsed, ac_info
  for attempt = 0, retries do
    if attempt > 0 then
      local delay = math.floor(backoff * 2 ^ (attempt - 1))
      stdnse.debug1("C-FIND: SCP busy (%s); retry %d/%d in %d ms",
        tostring(sock), attempt, retries, delay)
      stdnse.sleep(delay / 1000)
    end
    ok, sock, pctxs, server_max_pdu, elapsed, ac_info =
      dicom.do_associate(host, port, called_ae, calling_ae, sop_classes,
        max_pdu, timeout_s, transfer_uids, roles, tls)
    if ok or not is_busy_reject_str(sock) then break end
  end
  return ok, sock, pctxs, server_max_pdu, elapsed, ac_info
end

-- Common vendor Private Creator tags (gggg,0010) used when
-- dicom-cfind-ls.private_tags is set to "true" or "all".
local DEFAULT_PRIVATE_CREATOR_TAGS = {
  {group=0x0009, elem=0x0010, vr="LO", value=""},
  {group=0x0011, elem=0x0010, vr="LO", value=""},
  {group=0x0019, elem=0x0010, vr="LO", value=""},
  {group=0x0021, elem=0x0010, vr="LO", value=""},
  {group=0x0025, elem=0x0010, vr="LO", value=""},
  {group=0x0029, elem=0x0010, vr="LO", value=""},
  {group=0x0043, elem=0x0010, vr="LO", value=""},
  {group=0x7005, elem=0x0010, vr="LO", value=""},
}

-- Build private query tags. Per PS3.5 section 7.8.1, whenever a private data
-- element (gggg,xxee) (xx in 10..FF) is requested, automatically include its
-- Private Creator reservation tag (gggg,00xx) (VR=LO) if not already given, so
-- strict SCPs accept the block and return the creator name alongside the value.
local function build_private_query_tags(priv_arg)
  if not priv_arg or priv_arg == "" then return {} end
  local low = tostring(priv_arg):lower()
  if low == "false" or low == "no" or low == "0" or low == "off" then return {} end
  if low == "true" or low == "yes" or low == "1" or low == "all" or low == "on" then
    local copy = {}
    for i, t in ipairs(DEFAULT_PRIVATE_CREATOR_TAGS) do copy[i] = t end
    return copy
  end
  local parsed = dicom.parse_tag_spec(priv_arg)
  local creators_seen = {}
  for _, t in ipairs(parsed) do
    if dicom.is_private_tag(t.group) and t.elem >= 0x0010 and t.elem <= 0x00FF then
      creators_seen[string.format("%04X,%04X", t.group, t.elem)] = true
    end
  end
  local out = {}
  for _, t in ipairs(parsed) do
    if dicom.is_private_tag(t.group) and t.elem >= 0x1000 then
      local c_elem = math.floor(t.elem / 0x100)
      local c_key  = string.format("%04X,%04X", t.group, c_elem)
      if not creators_seen[c_key] then
        creators_seen[c_key] = true
        out[#out + 1] = { group = t.group, elem = c_elem, vr = "LO", value = "" }
      end
    end
    out[#out + 1] = t
  end
  return out
end

local function append_tags(dst, extra)
  local seen = {}
  for _, t in ipairs(dst) do
    seen[string.format("%04X,%04X", t.group, t.elem)] = true
  end
  for _, t in ipairs(extra) do
    local k = string.format("%04X,%04X", t.group, t.elem)
    if not seen[k] then
      seen[k] = true
      dst[#dst + 1] = t
    end
  end
end

local function clone_tags(src)
  local out = {}
  for i, t in ipairs(src) do out[i] = t end
  return out
end

local function format_private_lines(priv_list, indent)
  local out = {}
  for _, p in ipairs(priv_list or {}) do
    if p.is_creator then
      out[#out + 1] = string.format("%s[PrivateCreator %s] %s",
        indent, p.tag, p.value)
    elseif p.creator then
      out[#out + 1] = string.format("%s[Private %s (%s)] %s",
        indent, p.tag, p.creator, p.value)
    else
      out[#out + 1] = string.format("%s[Private %s] %s",
        indent, p.tag, p.value)
    end
  end
  return out
end

--- Hex-dump helper for debug level >= 2.
local function hexdump(label, data)
  if not data or #data == 0 or nmap.debugging() < 2 then return end
  local parts = {}
  for i = 1, #data do
    parts[#parts + 1] = string.format("%02X", string.byte(data, i))
    if i % 32 == 0 then parts[#parts + 1] = "\n  " end
  end
  stdnse.debug2("%s (%d bytes):\n  %s", label, #data, table.concat(parts, " "))
end

-----------------------------------------------------------------------
-- REUSABLE C-FIND SESSION
-----------------------------------------------------------------------
-- Reuses a single A-ASSOCIATE across sequential PATIENT/STUDY/SERIES/IMAGE
-- C-FIND queries (incrementing MessageID per PS3.7 section 9.1.2) so scanning
-- a PACS with dozens of studies does not open hundreds of TCP/TLS handshakes.
-- Transparently reconnects once if a legacy SCP closes the association after
-- a single C-FIND exchange.

local CfindSession = {}
CfindSession.__index = CfindSession

function CfindSession.new(host, port, called_ae, calling_ae, find_sop,
                          max_pdu, timeout_s, tls)
  return setmetatable({
    host            = host,
    port            = port,
    called_ae       = called_ae,
    calling_ae      = calling_ae,
    find_sop        = find_sop,
    max_pdu         = max_pdu,
    timeout_s       = timeout_s,
    tls             = tls,
    sock            = nil,
    pctx_id         = nil,
    ts              = nil,
    eff_max         = max_pdu,
    carry           = "",
    msg_id          = 0,
    dicom_confirmed = false,
  }, CfindSession)
end

function CfindSession:drop(send_abort)
  if self.sock then
    if send_abort then
      dicom.do_abort(self.sock)
    else
      pcall(function() self.sock:close() end)
    end
    self.sock = nil
  end
  self.pctx_id = nil
  self.carry = ""
end

function CfindSession:release()
  if self.sock then
    dicom.do_release(self.sock, 3)
    self.sock = nil
  end
  self.pctx_id = nil
  self.carry = ""
end

function CfindSession:ensure_open()
  if self.sock then return true end
  local cfind_ts = {
    dicom.TRANSFER_SYNTAX.EXPLICIT_LE,
    dicom.TRANSFER_SYNTAX.IMPLICIT_LE,
    dicom.TRANSFER_SYNTAX.EXPLICIT_BE,
  }
  local ok, sock, pctxs, server_max_pdu = associate_with_backoff(
    self.host, self.port, self.called_ae, self.calling_ae,
    {self.find_sop}, self.max_pdu, self.timeout_s, cfind_ts, nil, self.tls)
  if not ok then
    local err_s = tostring(sock)
    if err_s:find("^REJECT%(") or err_s == "A-ABORT" then
      self.dicom_confirmed = true
    end
    return false, err_s
  end

  self.dicom_confirmed = true
  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 3)
    return false, "NO_ACCEPTED_PCTX"
  end

  self.sock    = sock
  self.pctx_id = pctx_id
  self.ts      = dicom.get_accepted_ts(pctxs, pctx_id)
                 or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  self.eff_max = effective_max_pdu(server_max_pdu, self.max_pdu)
  self.carry   = ""
  self.msg_id  = 0
  return true
end

function CfindSession:query_once(query_tags, level, max_results)
  local was_reused = (self.sock ~= nil)
  local ok, err = self:ensure_open()
  if not ok then
    return false, err
  end

  self.msg_id = (self.msg_id % 65535) + 1
  local cur_msg_id = self.msg_id

  stdnse.debug1("C-FIND: level=%s msg_id=%d pctx_id=%d TS=%s max_pdu=%d tags=%d",
    level, cur_msg_id, self.pctx_id, self.ts, self.eff_max, #query_tags)

  local cmd_bytes = dicom.build_cfind_rq(cur_msg_id, self.find_sop)
  local ds_bytes  = dicom.build_cfind_dataset(level, clone_tags(query_tags), self.ts)

  hexdump("C-FIND command set", cmd_bytes)
  hexdump("C-FIND dataset", ds_bytes)

  local sent_ok = dicom.send_dimse(self.sock, self.pctx_id, cmd_bytes, ds_bytes, self.eff_max)
  if not sent_ok then
    self:drop(false)
    if was_reused then
      -- Legacy SCP closed the idle association between queries; reconnect once.
      return self:query_once(query_tags, level, max_results)
    end
    return false, "Failed to send C-FIND DIMSE message"
  end

  local results = {}
  local count = 0
  local cancelled = false
  local drain_count = 0

  while true do
    local pdu_type, cmd_elems, resp_ds_bytes, raw
    pdu_type, cmd_elems, resp_ds_bytes, raw, self.carry =
      dicom.recv_dimse(self.sock, self.timeout_s, self.carry)

    if not pdu_type then
      stdnse.debug1("C-FIND recv error: %s", tostring(raw))
      -- If a reused connection was cleanly closed by a single-query SCP before
      -- any bytes arrived for this query, reopen and retry once.
      if was_reused and count == 0 and tostring(raw) == "CONNECTION_RESET" then
        self:drop(false)
        return self:query_once(query_tags, level, max_results)
      end
      self:drop(true)
      if #results > 0 then return true, results end
      return false, tostring(raw)
    end

    if pdu_type == dicom.PDU_CODES.ABORT then
      stdnse.debug1("C-FIND: received A-ABORT from server (tags=%d, level=%s)",
          #query_tags, level)
      hexdump("A-ABORT PDU", raw)
      self:drop(false)
      if #results > 0 then return true, results end
      return false, "A-ABORT"
    end

    if pdu_type ~= dicom.PDU_CODES.DATA then
      stdnse.debug1("C-FIND: unexpected PDU type 0x%02X", pdu_type)
      self:drop(true)
      if #results > 0 then return true, results end
      return false, string.format("UNEXPECTED_PDU(0x%02X)", pdu_type)
    end

    local cfind_status = 0xFFFF
    if cmd_elems and cmd_elems["0000,0900"] then
      cfind_status = cmd_elems["0000,0900"].value
    end

    if cfind_status == dicom.STATUS.PENDING
       or cfind_status == dicom.STATUS.PENDING_WARN then
      if not cancelled then
        if #resp_ds_bytes > 0 then
          local ds_elems = dicom.parse_dataset(resp_ds_bytes, self.ts)
          if ds_elems then
            results[#results + 1] = ds_elems
            count = count + 1
            if count >= max_results then
              -- PS3.7 section 9.1.2.1.4: send C-CANCEL-RQ matching this
              -- request's MessageID and drain until CANCEL/SUCCESS.
              stdnse.debug1("C-FIND: max_results (%d) reached; sending C-CANCEL-RQ (msg_id=%d)",
                max_results, cur_msg_id)
              dicom.send_dimse(self.sock, self.pctx_id,
                dicom.build_ccancel_rq(cur_msg_id), nil, self.eff_max)
              cancelled = true
            end
          end
        end
      else
        drain_count = drain_count + 1
        if drain_count >= MAX_CANCEL_DRAIN then
          -- Guard against legacy SCPs that ignore C-CANCEL-RQ on large tables.
          stdnse.debug1("C-FIND: SCP did not honor C-CANCEL-RQ after %d PDUs; aborting association",
            drain_count)
          self:drop(true)
          return true, results
        end
      end
    elseif cfind_status == dicom.STATUS.SUCCESS
        or cfind_status == dicom.STATUS.CANCEL then
      stdnse.debug1("C-FIND: finished (status=0x%04X) -- %d results",
        cfind_status, #results)
      break
    else
      stdnse.debug1("C-FIND: status 0x%04X -- stopping", cfind_status)
      break
    end
  end

  return true, results
end

-- Perform a C-FIND query with automatic fallback to minimal tags on A-ABORT.
function CfindSession:query(query_tags, level, max_results, minimal_tags)
  local ok, results = self:query_once(query_tags, level, max_results)
  if ok then
    return true, results, false
  end

  if results == "A-ABORT" and minimal_tags and #query_tags > #minimal_tags then
    stdnse.debug1("C-FIND: A-ABORT with %d tags at %s; retrying with %d minimal tags",
      #query_tags, level, #minimal_tags)
    ok, results = self:query_once(minimal_tags, level, max_results)
    if ok then
      return true, results, true
    end
  end

  return false, results, false
end

-----------------------------------------------------------------------
-- C-GET RETRIEVAL
-----------------------------------------------------------------------

--- Build a DICOM Part 10 File Meta Information header (PS3.10 section 7.1).
local function build_part10_header(sop_class, sop_instance, ts_uid)
  local meta = dicom.explicit_elem(0x0002, 0x0001, "OB", "\x00\x01")
    .. dicom.explicit_elem(0x0002, 0x0002, "UI", sop_class or "")
    .. dicom.explicit_elem(0x0002, 0x0003, "UI", sop_instance or "")
    .. dicom.explicit_elem(0x0002, 0x0010, "UI", ts_uid or dicom.TRANSFER_SYNTAX.IMPLICIT_LE)
    .. dicom.explicit_elem(0x0002, 0x0012, "UI", dicom.IMPL_CLASS_UID)
    .. dicom.explicit_elem(0x0002, 0x0013, "SH", dicom.IMPL_VERSION)
  local grp_len = dicom.explicit_elem(0x0002, 0x0000, "UL", #meta)
  return string.rep("\x00", 128) .. "DICM" .. grp_len .. meta
end

--- Download DICOM instances via C-GET.
-- Handles incoming C-STORE sub-operations from the SCP and saves files.
local function do_cget(host, port, called_ae, calling_ae, get_sop,
                       storage_sops, query_tags, level, max_pdu,
                       timeout_s, save_dir, tls)
  local all_sops = {get_sop}
  local roles = {}
  -- PS3.8 allows at most 128 presentation contexts per A-ASSOCIATE-RQ (1 for
  -- get_sop + up to 127 Storage SOP classes).
  local limit = math.min(#storage_sops, 127)
  if #storage_sops > 127 then
    stdnse.debug1("C-GET: capping storage SOP classes at 127 (found %d)", #storage_sops)
  end
  for i = 1, limit do
    local sop = storage_sops[i]
    all_sops[#all_sops + 1] = sop
    -- PS3.7 D.3.3.4: request SCP role on each Storage SOP class so the peer
    -- can send C-STORE sub-operations back over this association.
    roles[#roles + 1] = { uid = sop, scu = true, scp = true }
  end

  local ok, sock, pctxs, server_max_pdu = associate_with_backoff(
    host, port, called_ae, calling_ae, all_sops, max_pdu,
    timeout_s, nil, roles, tls)
  if not ok then
    return 0, 0, sock
  end

  -- PC ID 1 is always get_sop (first entry in all_sops).
  local pctx_id = pctxs[1] and pctxs[1].accepted and 1 or nil
  if not pctx_id then
    dicom.do_release(sock, 3)
    return 0, 0, "No accepted presentation context for C-GET"
  end

  local ts = dicom.get_accepted_ts(pctxs, pctx_id)
      or dicom.TRANSFER_SYNTAX.EXPLICIT_LE
  local eff_max = effective_max_pdu(server_max_pdu, max_pdu)

  -- Build and send C-GET-RQ
  local cmd_bytes = dicom.build_cget_rq(1, get_sop)
  local ds_bytes  = dicom.build_cfind_dataset(level, clone_tags(query_tags), ts)

  local sent_ok = dicom.send_dimse(sock, pctx_id, cmd_bytes, ds_bytes, eff_max)
  if not sent_ok then
    dicom.do_abort(sock)
    return 0, 0, "Failed to send C-GET-RQ"
  end

  local saved, errors = 0, 0
  local carry = ""
  local clean_end = false
  local peer_aborted = false

  while true do
    local pdu_type, cmd_elems, resp_ds, raw, sub_pctx_id
    pdu_type, cmd_elems, resp_ds, raw, carry, sub_pctx_id =
      dicom.recv_dimse(sock, timeout_s, carry)

    if not pdu_type then
      stdnse.debug1("C-GET recv error: %s", tostring(raw))
      break
    end
    if pdu_type == dicom.PDU_CODES.ABORT then
      stdnse.debug1("C-GET: received A-ABORT")
      peer_aborted = true
      break
    end
    if pdu_type ~= dicom.PDU_CODES.DATA then
      stdnse.debug1("C-GET: unexpected PDU 0x%02X", pdu_type)
      break
    end

    local cmd_field = 0
    if cmd_elems and cmd_elems["0000,0100"] then
      cmd_field = cmd_elems["0000,0100"].value
    end

    if cmd_field == dicom.COMMAND_FIELD.C_STORE_RQ then
      local sop_class = ""
      if cmd_elems["0000,0002"] then
        sop_class = tostring(cmd_elems["0000,0002"].value):gsub("%z", ""):gsub("%s+$", "")
      end
      local sop_instance = ""
      if cmd_elems["0000,1000"] then
        sop_instance = tostring(cmd_elems["0000,1000"].value):gsub("%z", ""):gsub("%s+$", "")
      end
      if sop_instance == "" then sop_instance = dicom.generate_fake_uid() end
      local msg_id_rsp = 1
      if cmd_elems["0000,0110"] then
        msg_id_rsp = cmd_elems["0000,0110"].value
      end

      -- Sanitize SOP Instance UID for filesystem safety (no separators or leading dots).
      local safe_name = sop_instance:gsub("[^%w%.%-_]", "_"):gsub("^%.+", "")
      if safe_name == "" then safe_name = dicom.generate_fake_uid() end
      local filename = safe_name .. ".dcm"
      local filepath = save_dir:gsub("[/\\]+$", "") .. "/" .. filename
      local store_ts = (sub_pctx_id and dicom.get_accepted_ts(pctxs, sub_pctx_id)) or ts
      local file_data = (resp_ds and #resp_ds > 0)
        and (build_part10_header(sop_class, sop_instance, store_ts) .. resp_ds)
        or (resp_ds or "")
      local wok, werr = dicom.write_file(filepath, file_data)
      if wok then
        saved = saved + 1
        stdnse.debug1("C-GET: saved %s (%d bytes)", filename, #file_data)
      else
        errors = errors + 1
        stdnse.debug1("C-GET: save failed: %s", tostring(werr))
      end

      -- Reply on the C-STORE presentation context the sub-operation arrived on.
      local rsp_cmd = dicom.build_cstore_rsp(msg_id_rsp, sop_class, sop_instance)
      dicom.send_dimse(sock, sub_pctx_id or pctx_id, rsp_cmd, nil, eff_max)

    elseif cmd_field == dicom.COMMAND_FIELD.C_GET_RSP then
      local cget_status = 0xFFFF
      if cmd_elems["0000,0900"] then
        cget_status = cmd_elems["0000,0900"].value
      end
      if cget_status ~= dicom.STATUS.PENDING
         and cget_status ~= dicom.STATUS.PENDING_WARN then
        stdnse.debug1("C-GET: final RSP status 0x%04X", cget_status)
        clean_end = true
        break
      end
    else
      stdnse.debug1("C-GET: unknown command field 0x%04X", cmd_field)
    end
  end

  if peer_aborted then
    pcall(function() sock:close() end)
  elseif clean_end then
    dicom.do_release(sock, 3)
  else
    dicom.do_abort(sock)
  end
  return saved, errors
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------

action = function(host, port)
  local called_ae   = get_arg("called_ae",
                        stdnse.get_script_args("dicom.called_aet") or "ANY-SCP")
  local calling_ae  = get_arg("calling_ae",
                        stdnse.get_script_args("dicom.calling_aet") or "FINDSCU")
  local max_level   = tostring(get_arg("level", "IMAGE")):upper()
  if not VALID_LEVELS[max_level] then
    stdnse.debug1("Unknown level %q; defaulting to IMAGE", max_level)
    max_level = "IMAGE"
  end
  local max_results = math.max(1, math.floor(tonumber(get_arg("max_results", 100)) or 100))
  local timeout_s   = math.max(1, tonumber(get_arg("timeout", 10)) or 10)
  local max_pdu     = math.max(512, math.floor(tonumber(get_arg("max_pdu", 16384)) or 16384))
  local pat_name    = tostring(get_arg("patient_name", "*"))
  local pat_id      = tostring(get_arg("patient_id",   ""))
  local study_date  = tostring(get_arg("study_date",   ""))
  local modality    = tostring(get_arg("modality",     ""))
  local save_dir    = get_arg("save", nil)
  local explicit_model = stdnse.get_script_args("dicom-cfind-ls.info_model")
  local info_model  = tostring(explicit_model or "study"):lower()
  local priv_tags   = build_private_query_tags(get_arg("private_tags", nil))
  local want_extra  = dicom.parse_bool_arg(get_arg("full", nil), false)
                      or study_date ~= ""
                      or modality ~= ""

  local is_tls   = dicom.tls_enabled(port)
  local verbose  = nmap.verbosity() > 1
  local debug_on = nmap.debugging() > 0

  -- PATIENT level requires the Patient Root Q/R model (PS3.4 Annex C).
  local find_sop, get_sop
  if info_model == "patient" or max_level == "PATIENT" then
    info_model = "patient"
    find_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.PATIENT_ROOT_QR_GET
  else
    info_model = "study"
    find_sop = dicom.SOP_CLASS.STUDY_ROOT_QR_FIND
    get_sop  = dicom.SOP_CLASS.STUDY_ROOT_QR_GET
  end

  local out = stdnse.output_table()

  -- Run the entire C-FIND hierarchy under the per-host DICOM mutex so
  -- concurrent scripts (dicom-ping, dicom-info, multiple ports) never
  -- open parallel associations to the same PACS.
  local run_ok, run_err, used_fallback, patients, patient_order,
        study_count, series_count, instance_count, dicom_confirmed

  run_ok, run_err, used_fallback, patients, patient_order,
  study_count, series_count, instance_count, dicom_confirmed =
    dicom.with_host_lock(host, function()
      local sess = CfindSession.new(host, port, called_ae, calling_ae,
        find_sop, max_pdu, timeout_s, is_tls)

      local function build_study_tags(for_patient_id)
        local base = {}
        if info_model == "patient" then
          -- PS3.4 section C.6.1.1.3: Patient Root STUDY level is keyed by
          -- PatientID (0010,0020), not PatientName.
          base[#base + 1] = {group=0x0010, elem=0x0020, vr="LO", value=for_patient_id}
          base[#base + 1] = {group=0x0020, elem=0x000D, vr="UI", value=""}
        else
          base[#base + 1] = {group=0x0010, elem=0x0010, vr="PN", value=pat_name}
          base[#base + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat_id}
          base[#base + 1] = {group=0x0020, elem=0x000D, vr="UI", value=""}
        end
        local tags = clone_tags(base)
        if want_extra then
          if info_model == "study" then
            tags[#tags + 1] = {group=0x0010, elem=0x0030, vr="DA", value=""}
            tags[#tags + 1] = {group=0x0010, elem=0x0040, vr="CS", value=""}
          end
          tags[#tags + 1] = {group=0x0008, elem=0x0020, vr="DA", value=study_date}
          tags[#tags + 1] = {group=0x0008, elem=0x0030, vr="TM", value=""}
          tags[#tags + 1] = {group=0x0008, elem=0x0050, vr="SH", value=""}
          tags[#tags + 1] = {group=0x0008, elem=0x0061, vr="CS", value=modality}
          tags[#tags + 1] = {group=0x0008, elem=0x1030, vr="LO", value=""}
          tags[#tags + 1] = {group=0x0020, elem=0x0010, vr="SH", value=""}
        end
        append_tags(tags, priv_tags)
        return tags, base
      end

      local pats = {}
      local pat_order = {}
      local st_count = 0
      local sr_count = 0
      local inst_count = 0
      local any_fallback = false
      local anon_counter = 0

      local function ensure_patient(pid_raw, pname_raw, psex, pdob, ppriv)
        local pid = first_nonempty(pid_raw, "UNKNOWN")
        local pname = first_nonempty(pname_raw, "UNKNOWN")
        local pkey = pid
        if pid == "UNKNOWN" then
          -- Avoid merging distinct unidentified patients under one key.
          if pname ~= "UNKNOWN" then
            pkey = "UNKNOWN|" .. pname
          else
            anon_counter = anon_counter + 1
            pkey = "UNKNOWN#" .. tostring(anon_counter)
          end
        end
        if not pats[pkey] then
          pats[pkey] = {
            id           = pid,
            name         = pname,
            sex          = psex or "",
            dob          = pdob or "",
            private_tags = ppriv or {},
            studies      = {},
          }
          pat_order[#pat_order + 1] = pkey
        end
        return pats[pkey]
      end

      -- Helper to run the initial top-level query, with Study->Patient Root
      -- automatic fallback when the user did not pin info_model.
      local function run_top_query()
        if info_model == "patient" then
          local base_pat = {
            {group=0x0010, elem=0x0010, vr="PN", value=pat_name},
            {group=0x0010, elem=0x0020, vr="LO", value=pat_id},
          }
          local pat_tags = clone_tags(base_pat)
          if want_extra then
            pat_tags[#pat_tags + 1] = {group=0x0010, elem=0x0030, vr="DA", value=""}
            pat_tags[#pat_tags + 1] = {group=0x0010, elem=0x0040, vr="CS", value=""}
          end
          append_tags(pat_tags, priv_tags)
          local ok, rows, fb = sess:query(pat_tags, "PATIENT", max_results, base_pat)
          if not ok then return false, rows end
          if fb then any_fallback = true end
          for _, p in ipairs(rows) do
            ensure_patient(p["0010,0020"], p["0010,0010"],
              p["0010,0040"], p["0010,0030"], dicom.extract_private_tags(p))
          end
          -- Patient Root STUDY-level drilldown (PS3.4 section C.6.1.1.3)
          if max_level ~= "PATIENT" then
            for _, pkey in ipairs(pat_order) do
              local pat = pats[pkey]
              if pat.id ~= "UNKNOWN" then
                local stags, sbase = build_study_tags(pat.id)
                local sok, srows, sfb = sess:query(stags, "STUDY", max_results, sbase)
                if sfb then any_fallback = true end
                if sok and srows then
                  for _, s in ipairs(srows) do
                    pat.studies[#pat.studies + 1] = {
                      uid          = s["0020,000D"] or "",
                      date         = s["0008,0020"] or "",
                      time         = s["0008,0030"] or "",
                      description  = s["0008,1030"] or "",
                      modality     = first_nonempty(s["0008,0060"], s["0008,0061"]),
                      study_id     = s["0020,0010"] or "",
                      accession    = s["0008,0050"] or "",
                      private_tags = dicom.extract_private_tags(s),
                      series       = {},
                    }
                    st_count = st_count + 1
                  end
                end
              end
            end
          end
          return true
        else
          local stags, sbase = build_study_tags("")
          local ok, rows, fb = sess:query(stags, "STUDY", max_results, sbase)
          if not ok and rows == "NO_ACCEPTED_PCTX" and not explicit_model then
            -- Auto-fallback to Patient Root for legacy SCPs that do not
            -- implement Study Root Q/R.
            stdnse.debug1("C-FIND: Study Root not accepted; falling back to Patient Root")
            info_model = "patient"
            find_sop = dicom.SOP_CLASS.PATIENT_ROOT_QR_FIND
            get_sop  = dicom.SOP_CLASS.PATIENT_ROOT_QR_GET
            sess:drop(false)
            sess.find_sop = find_sop
            return run_top_query()
          end
          if not ok then return false, rows end
          if fb then any_fallback = true end
          for _, s in ipairs(rows) do
            local pat = ensure_patient(s["0010,0020"], s["0010,0010"],
              s["0010,0040"], s["0010,0030"], {})
            pat.studies[#pat.studies + 1] = {
              uid          = s["0020,000D"] or "",
              date         = s["0008,0020"] or "",
              time         = s["0008,0030"] or "",
              description  = s["0008,1030"] or "",
              modality     = first_nonempty(s["0008,0060"], s["0008,0061"]),
              study_id     = s["0020,0010"] or "",
              accession    = s["0008,0050"] or "",
              private_tags = dicom.extract_private_tags(s),
              series       = {},
            }
            st_count = st_count + 1
          end
          return true
        end
      end

      local top_ok, top_err = run_top_query()
      if not top_ok then
        sess:release()
        return false, top_err, any_fallback, pats, pat_order,
               st_count, sr_count, inst_count, sess.dicom_confirmed
      end

      -- SERIES-level C-FIND
      if max_level == "SERIES" or max_level == "IMAGE" then
        for _, pkey in ipairs(pat_order) do
          local pat = pats[pkey]
          for _, study in ipairs(pat.studies) do
            if study.uid ~= "" then
              local base_series = {
                {group=0x0008, elem=0x0060, vr="CS", value=""},
                {group=0x0008, elem=0x103E, vr="LO", value=""},
                {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
                {group=0x0020, elem=0x000E, vr="UI", value=""},
                {group=0x0020, elem=0x0011, vr="IS", value=""},
              }
              if info_model == "patient" and pat.id ~= "UNKNOWN" then
                base_series[#base_series + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat.id}
              end
              local min_series = {
                {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
                {group=0x0020, elem=0x000E, vr="UI", value=""},
              }
              if info_model == "patient" and pat.id ~= "UNKNOWN" then
                min_series[#min_series + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat.id}
              end
              local series_tags = clone_tags(base_series)
              append_tags(series_tags, priv_tags)

              local sok, series_list = sess:query(series_tags, "SERIES", max_results,
                #priv_tags > 0 and base_series or min_series)
              if sok and series_list then
                for _, sr in ipairs(series_list) do
                  study.series[#study.series + 1] = {
                    uid          = sr["0020,000E"] or "",
                    modality     = sr["0008,0060"] or "",
                    description  = sr["0008,103E"] or "",
                    number       = sr["0020,0011"] or "",
                    private_tags = dicom.extract_private_tags(sr),
                    instances    = {},
                    num_images   = 0,
                  }
                  sr_count = sr_count + 1
                end
              end
            end
          end
        end
      end

      -- IMAGE-level C-FIND
      if max_level == "IMAGE" then
        for _, pkey in ipairs(pat_order) do
          local pat = pats[pkey]
          for _, study in ipairs(pat.studies) do
            for _, series in ipairs(study.series) do
              if series.uid ~= "" then
                local base_img = {
                  {group=0x0008, elem=0x0016, vr="UI", value=""},
                  {group=0x0008, elem=0x0018, vr="UI", value=""},
                  {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
                  {group=0x0020, elem=0x000E, vr="UI", value=series.uid},
                  {group=0x0020, elem=0x0013, vr="IS", value=""},
                }
                if info_model == "patient" and pat.id ~= "UNKNOWN" then
                  base_img[#base_img + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat.id}
                end
                local min_img = {
                  {group=0x0008, elem=0x0016, vr="UI", value=""},
                  {group=0x0008, elem=0x0018, vr="UI", value=""},
                  {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
                  {group=0x0020, elem=0x000E, vr="UI", value=series.uid},
                }
                if info_model == "patient" and pat.id ~= "UNKNOWN" then
                  min_img[#min_img + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat.id}
                end
                local img_tags = clone_tags(base_img)
                append_tags(img_tags, priv_tags)

                local iok, imgs = sess:query(img_tags, "IMAGE", max_results,
                  #priv_tags > 0 and base_img or min_img)
                if iok and imgs then
                  for _, img in ipairs(imgs) do
                    series.instances[#series.instances + 1] = {
                      sop_class    = img["0008,0016"] or "",
                      sop_instance = img["0008,0018"] or "",
                      number       = img["0020,0013"] or "",
                      private_tags = dicom.extract_private_tags(img),
                    }
                    inst_count = inst_count + 1
                  end
                  series.num_images = #series.instances
                end
              end
            end
          end
        end
      end

      sess:release()
      return true, nil, any_fallback, pats, pat_order,
             st_count, sr_count, inst_count, sess.dicom_confirmed
    end)

  if not run_ok then
    local err_s = tostring(run_err)
    if not dicom_confirmed and not err_s:find("^REJECT%(") and err_s ~= "A-ABORT" then
      stdnse.debug1("C-FIND failed on unconfirmed endpoint: %s", err_s)
      return nil
    end
    if err_s == "NO_ACCEPTED_PCTX" then
      out["Error"] = "No accepted presentation context for C-FIND"
    elseif err_s == "A-ABORT" then
      out["Error"] = string.format(
        "C-FIND aborted by server (A-ABORT). " ..
        "The server may require a recognized calling AE title or have Query/Retrieve disabled " ..
        "(tried calling_ae='%s', called_ae='%s').",
        calling_ae, called_ae)
    else
      out["Error"] = string.format("C-FIND failed: %s", err_s)
    end
    return out
  end

  if used_fallback and verbose then
    stdnse.verbose1("C-FIND: server aborted with extended tags; used minimal query")
  end

  if #patient_order == 0 then
    out["Result"] = "No studies found (server may require specific AE title or filter)"
    return out
  end

  -- C-GET DOWNLOAD (if save option is set)
  local saved_total = 0
  if save_dir and max_level == "IMAGE" and instance_count > 0 then
    mkdir_p(save_dir)

    local sop_set = {}
    local storage_sops = {}
    for _, pkey in ipairs(patient_order) do
      for _, study in ipairs(patients[pkey].studies) do
        for _, series in ipairs(study.series) do
          for _, inst in ipairs(series.instances) do
            if inst.sop_class ~= "" and not sop_set[inst.sop_class] then
              sop_set[inst.sop_class] = true
              storage_sops[#storage_sops + 1] = inst.sop_class
            end
          end
        end
      end
    end

    dicom.with_host_lock(host, function()
      for _, pkey in ipairs(patient_order) do
        local pat = patients[pkey]
        for _, study in ipairs(pat.studies) do
          if study.uid ~= "" then
            local get_tags = {
              {group=0x0020, elem=0x000D, vr="UI", value=study.uid},
            }
            if info_model == "patient" and pat.id ~= "UNKNOWN" then
              get_tags[#get_tags + 1] = {group=0x0010, elem=0x0020, vr="LO", value=pat.id}
            end
            local nsaved = do_cget(host, port, called_ae, calling_ae,
              get_sop, storage_sops, get_tags, "STUDY", max_pdu,
              timeout_s, save_dir, is_tls)
            saved_total = saved_total + nsaved
            if nsaved > 0 then
              stdnse.verbose1("C-GET: saved %d instances for study %s", nsaved, study.uid)
            end
          end
        end
      end
    end)
  end

  -- FORMAT OUTPUT
  local model_name = info_model == "patient" and "Patient Root" or "Study Root"
  out["DICOM Q/R Results"] = string.format("(%s, FIND)", model_name)
  out["Patients"] = #patient_order
  if study_count > 0 or max_level ~= "PATIENT" then out["Studies"] = study_count end
  if series_count > 0 then out["Series"] = series_count end
  if instance_count > 0 then out["Instances"] = instance_count end

  local lines = {}
  for _, pkey in ipairs(patient_order) do
    local p = patients[pkey]
    local pline = string.format("[Patient] %s (ID: %s)", p.name, p.id)
    if p.sex ~= "" then pline = pline .. " " .. p.sex end
    if p.dob ~= "" then pline = pline .. " DOB:" .. p.dob end
    lines[#lines + 1] = pline
    for _, pl in ipairs(format_private_lines(p.private_tags, "  ")) do
      lines[#lines + 1] = pl
    end

    for _, study in ipairs(p.studies) do
      local sline = string.format("  [Study] %s",
        study.date ~= "" and study.date or "no-date")
      if study.description ~= "" then
        sline = sline .. " - " .. study.description
      end
      if study.modality ~= "" then
        sline = sline .. " (" .. study.modality .. ")"
      end
      if study.uid ~= "" then sline = sline .. " " .. study.uid end
      lines[#lines + 1] = sline
      for _, pl in ipairs(format_private_lines(study.private_tags, "    ")) do
        lines[#lines + 1] = pl
      end

      for _, series in ipairs(study.series) do
        local srline = string.format("    [Series] #%s %s",
          series.number ~= "" and series.number or "?",
          series.modality)
        if series.description ~= "" then
          srline = srline .. " - " .. series.description
        end
        if series.num_images > 0 then
          srline = srline .. string.format(" (%d images)", series.num_images)
        end
        if series.uid ~= "" then srline = srline .. " " .. series.uid end
        lines[#lines + 1] = srline
        for _, pl in ipairs(format_private_lines(series.private_tags, "      ")) do
          lines[#lines + 1] = pl
        end

        for ii, inst in ipairs(series.instances) do
          local show_inst = debug_on or (verbose and ii <= 5)
          if show_inst then
            local iline = string.format("      [Instance] #%s %s (%s)",
              inst.number ~= "" and tostring(inst.number) or "?",
              tostring(inst.sop_instance), tostring(inst.sop_class))
            lines[#lines + 1] = iline
            for _, pl in ipairs(format_private_lines(inst.private_tags, "        ")) do
              lines[#lines + 1] = pl
            end
          elseif verbose and ii == 6 then
            lines[#lines + 1] = string.format(
              "      ... and %d more instances (use -d for all)",
              #series.instances - 5)
          end
        end
      end
    end
  end

  out["Listing"] = lines

  if #patient_order > 0 then
    out["WARNING"] = "Patient data accessible without authentication"
  end

  if saved_total > 0 then
    out["Saved"] = string.format("%d instances to %s", saved_total, save_dir)
  elseif save_dir and instance_count == 0 then
    out["Save"] = "No instances found to download"
  elseif save_dir and max_level ~= "IMAGE" then
    out["Save"] = "Set level=IMAGE to enable C-GET download"
  end

  nmap.set_port_state(host, port, "open")
  port.version.name = is_tls and "dicom-tls" or "dicom"
  nmap.set_port_version(host, port)

  return out
end
