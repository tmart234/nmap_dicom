-- nmap_dicom: luacheck config for upstream PR readiness.
-- Run `luacheck nselib/dicom.lua scripts/dicom-enum.nse scripts/dicom-ping.nse`
-- from the repo root (NSE files have a .nse extension and aren't picked up by
-- the default `nselib/ scripts/` recursion).
std = "lua54"
self = false
-- NSE scripts ship wide PC_LIST / @xmloutput sample lines; the 120-col
-- default would force gratuitous wrapping in code that has been formatted
-- consistently against upstream Nmap conventions.
max_line_length = 250

read_globals = {
  "nmap", "stdnse", "string", "table", "math", "shortport", "ipOps", "tab",
  "io", "os", "bin", "tableaux", "json", "openssl", "datetime",
}

-- NSE script-globals (set at top of every .nse file).
globals = {
  "description", "categories", "author", "license",
  "portrule", "hostrule", "action", "dependencies",
}

ignore = {
  "211/_.+",   -- unused locals named _foo (idiomatic discard)
  "212/_.+",   -- unused arguments named _foo
  "212/self",
  "213/_.+",   -- unused-loop-variable
  "231/_.+",   -- never-accessed locals named _foo (multi-return discards)
  "542",       -- empty if branch (used as documented no-op)
}

-- nselib modules use the stdnse.module(_ENV-based) idiom which luacheck
-- doesn't natively understand.
files["nselib/dicom.lua"] = {
  globals = {
    "_ENV",
    -- exported by `_ENV = stdnse.module(...)`:
    "PDU_NAMES", "PDU_CODES",
    "PC_RESULT_NAMES", "TRANSFER_SYNTAX_UIDS", "TRANSFER_SYNTAX_NAMES",
    "ASSOC_RJ_RESULT", "ASSOC_RJ_SOURCE", "ASSOC_RJ_REASON",
    "SERVICE_CLASS_BY_UID",
    "service_class_for_uid", "infer_device_class",
    "start_connection", "send", "receive", "pdu_header_encode",
    "parse_associate_accept", "parse_implementation_version",
    "identify_vendor_from_uid", "identify_toolkit", "extract_clean_version",
    "resolve_vendor_info", "associate_extended", "associate",
    "send_pdata", "extract_uid_root",
  },
}
