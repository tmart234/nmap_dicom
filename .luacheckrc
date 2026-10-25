-- nmap_dicom: luacheck config for upstream PR readiness.
-- Run `luacheck nselib/dicom.lua scripts/*.nse`
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
  "SCRIPT_NAME", "SCRIPT_PATH", "SCRIPT_TYPE",
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

-- nselib modules use the `_ENV = stdnse.module(...)` idiom: every top-level
-- global assignment after it is an exported module member.
files["nselib/dicom.lua"] = {
  globals = { "_ENV" },
  allow_defined_top = true,
  ignore = { "131" },  -- exported members are "unused" within the module
}
