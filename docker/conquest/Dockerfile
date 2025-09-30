# ---------- Stage 1: Builder ----------
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_USER=marcelvanherk
ARG CONQUEST_GIT_PROJECT_NAME=Conquest-DICOM-Server
ARG CONQUEST_GIT_REPO_URL=https://github.com/${CONQUEST_GIT_USER}/${CONQUEST_GIT_PROJECT_NAME}.git
ARG CONQUEST_GIT_BRANCH=master
ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

# Build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates git make g++ lua5.1 liblua5.1-0-dev gettext-base curl \
    && rm -rf /var/lib/apt/lists/*

# Source
RUN echo "Cloning Conquest from ${CONQUEST_GIT_REPO_URL} (${CONQUEST_GIT_BRANCH}) -> ${CONQUEST_SRC_DIR}"
RUN git clone --depth 1 --branch ${CONQUEST_GIT_BRANCH} ${CONQUEST_GIT_REPO_URL} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}
RUN echo "--- Listing ${CONQUEST_SRC_DIR} after clone ---" && ls -lA .

# Stage default configs (no heredocs; use printf)
ARG DICOM_INI=dicom.ini
ARG ACRNEMA_MAP=acrnema.map
ARG DGATESOP_LST=dgatesop.lst
ARG DICOM_SQL=dicom.sql

RUN set -e; \
  echo "Creating ${TEMP_CONFIG_DIR} and staging defaults"; \
  mkdir -p "${TEMP_CONFIG_DIR}"; \
  for f in "${DICOM_INI}" "${ACRNEMA_MAP}" "${DGATESOP_LST}" "${DICOM_SQL}"; do \
    found=""; \
    for p in "." "install" "install64" "install32" "linux" "docker"; do \
      if [ -f "${p}/${f}" ]; then \
        echo "Found ${p}/${f} -> ${TEMP_CONFIG_DIR}/${f}.default"; \
        cp -v "${p}/${f}" "${TEMP_CONFIG_DIR}/${f}.default"; \
        found="yes"; break; \
      fi; \
    done; \
    [ -n "$found" ] || echo "Will synthesize ${f}"; \
  done; \
  if [ ! -f "${TEMP_CONFIG_DIR}/${DICOM_INI}.default" ]; then \
    printf '%s\n' \
      '[sscscp]' \
      'MicroPACS                = sscscp' \
      'TCPPort                  = 5678' \
      'MyACRNema                = CONQUESTSRV1' \
      'PACSName                 = CONQUESTSRV1' \
      'HostComputer             = linux' \
      'Dictionary               = dgate.dic' \
      'MAG0                     = /opt/conquest/data/' \
      'FileNameSyntax           = 4' \
      '# Minimal config for bring-up and C-ECHO. Mount your own dicom.ini for DB use.' \
      > "${TEMP_CONFIG_DIR}/${DICOM_INI}.default"; \
  fi; \
  if [ ! -f "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default" ]; then \
    printf '%s\n' \
      '# AE           IP           Port  Compress' \
      'CONQUESTSRV1  127.0.0.1    5678  un' \
      > "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default"; \
  fi; \
  if [ ! -f "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default" ]; then \
    : > "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default"; \
  fi; \
  if [ ! -f "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default" ]; then \
    : > "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default"; \
  fi; \
  echo "--- Contents of ${TEMP_CONFIG_DIR} ---"; \
  ls -lA "${TEMP_CONFIG_DIR}"

# Build Conquest
RUN chmod +x linux/maklinux_precompiled src/servertask/make.sh
RUN echo "Running linux/maklinux_precompiled..." && linux/maklinux_precompiled
RUN echo "Running src/servertask/make.sh..." && cd src/servertask && ./make.sh
RUN echo "--- Listing after build ---" && ls -lA .
RUN echo "dgate present? $(if [ -f dgate ]; then echo yes; else echo no; fi)"
RUN echo "servertask present? $(if [ -f src/servertask/servertask ]; then echo yes; else echo no; fi)"

# ---------- Stage 2: Runtime ----------
FROM ubuntu:20.04

ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      liblua5.1-0 ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/conquest/data /opt/conquest/config /opt/conquest/defaults

# Binaries
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate                     /usr/local/bin/dgate
COPY --from=builder ${CONQUEST_SRC_DIR}/src/servertask/servertask /usr/local/bin/servertask

# Default configs
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.ini.default          /opt/conquest/defaults/dicom.ini.default
COPY --from=builder ${TEMP_CONFIG_DIR}/acrnema.map.default        /opt/conquest/defaults/acrnema.map.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dgatesop.lst.default       /opt/conquest/defaults/dgatesop.lst.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.sql.default          /opt/conquest/defaults/dicom.sql.default
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate.dic                 /opt/conquest/defaults/dgate.dic

# Entrypoint (no heredocs; careful with line continuations)
RUN printf '%s\n' \
'#!/bin/sh' \
'set -e' \
'CFG=/opt/conquest/config' \
'DEF=/opt/conquest/defaults' \
'mkdir -p "$CFG" /opt/conquest/data' \
'chmod 0777 /opt/conquest/data' \
'[ -f "$CFG/dgate.dic" ]     || cp "$DEF/dgate.dic"            "$CFG/dgate.dic"' \
'[ -f "$CFG/dicom.ini" ]     || cp "$DEF/dicom.ini.default"    "$CFG/dicom.ini"' \
'[ -f "$CFG/acrnema.map" ]   || cp "$DEF/acrnema.map.default"  "$CFG/acrnema.map"' \
'[ -f "$CFG/dgatesop.lst" ]  || cp "$DEF/dgatesop.lst.default" "$CFG/dgatesop.lst"' \
'[ -f "$CFG/dicom.sql" ]     || cp "$DEF/dicom.sql.default"    "$CFG/dicom.sql"' \
'grep -qi "^MAG0" "$CFG/dicom.ini" || printf "\nMAG0 = /opt/conquest/data/\n" >> "$CFG/dicom.ini"' \
'# Disable any kFactorFile setting to avoid parsing errors in CI' \
'sed -i -E "s/^[[:space:]]*k[fF]actor[fF]ile.*/; kFactorFile disabled for CI/" "$CFG/dicom.ini"' \
'# Ensure dicom.sql is empty/valid (no "--" lines)' \
': > "$CFG/dicom.sql"' \
'# Helpful defaults for visibility' \
'grep -qi "^DebugLevel" "$CFG/dicom.ini" || printf "DebugLevel = 4\n" >> "$CFG/dicom.ini"' \
'grep -qi "^MaxAssociations" "$CFG/dicom.ini" || printf "MaxAssociations = 32\n" >> "$CFG/dicom.ini"' \
'# Sanity dump' \
'echo "Config prepared in $CFG:"' \
'ls -l "$CFG" || true' \
'echo "--- dicom.ini ---"' \
'sed -n "1,120p" "$CFG/dicom.ini" || true' \
'# Symlinks for legacy default lookup' \
'ln -sf "$CFG/dicom.ini"  /usr/local/bin/dicom.ini' \
'ln -sf "$CFG/dgate.dic"  /usr/local/bin/dgate.dic' \
'ln -sf "$CFG/dicom.sql"  /usr/local/bin/dicom.sql' \
'echo "Starting dgate..."' \
'exec /usr/local/bin/dgate -v -c "$CFG/dicom.ini"' \
> /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt/conquest/data
EXPOSE 5678
CMD ["/usr/local/bin/entrypoint.sh"]
