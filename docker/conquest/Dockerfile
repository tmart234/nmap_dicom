# Stage 1: Builder based on Ubuntu 20.04
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
      ca-certificates git make g++ \
      lua5.1 liblua5.1-0-dev gettext-base curl \
    && rm -rf /var/lib/apt/lists/*

# Clone
RUN echo "Cloning Conquest from ${CONQUEST_GIT_REPO_URL} (${CONQUEST_GIT_BRANCH}) -> ${CONQUEST_SRC_DIR}"
RUN git clone --depth 1 --branch ${CONQUEST_GIT_BRANCH} ${CONQUEST_GIT_REPO_URL} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}
RUN echo "--- Listing ${CONQUEST_SRC_DIR} after clone ---" && ls -lA .

# Stage default config files (copy if present; otherwise synthesize)
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
        found="yes"; \
        break; \
      fi; \
    done; \
    [ -n "$found" ] || echo "Will synthesize ${f}"; \
  done; \
  # dicom.ini
  if [ ! -f "${TEMP_CONFIG_DIR}/${DICOM_INI}.default" ]; then \
    printf '%s\n' \
      "[sscscp]" \
      "MicroPACS                = sscscp" \
      "TCPPort                  = 5678" \
      "MyACRNema                = CONQUESTSRV1" \
      "PACSName                 = CONQUESTSRV1" \
      "HostComputer             = linux" \
      "Dictionary               = dgate.dic" \
      "# Minimal config for echo testing; mount a full dicom.ini for DB, etc." \
      > "${TEMP_CONFIG_DIR}/${DICOM_INI}.default"; \
  fi; \
  # acrnema.map
  if [ ! -f "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default" ]; then \
    printf '%s\n' \
      "# AE        IP           Port  Compress" \
      "CONQUESTSRV1 127.0.0.1   5678  un" \
      > "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default"; \
  fi; \
  # dgatesop.lst
  if [ ! -f "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default" ]; then \
    : > "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default"; \
  fi; \
  # dicom.sql (placeholder)
  if [ ! -f "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default" ]; then \
    printf '%s\n' \
      "-- Placeholder schema for basic container startup; mount a real dicom.sql for DB-backed use." \
      > "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default"; \
  fi; \
  echo "--- Contents of ${TEMP_CONFIG_DIR} ---"; \
  ls -lA "${TEMP_CONFIG_DIR}"

# Build
RUN chmod +x linux/maklinux_precompiled src/servertask/make.sh
RUN echo "Running linux/maklinux_precompiled..." && linux/maklinux_precompiled
RUN echo "Running src/servertask/make.sh..." && cd src/servertask && ./make.sh

# Verify
RUN echo "--- Listing after build ---" && ls -lA .
RUN echo "dgate present? $(if [ -f dgate ]; then echo yes; else echo no; fi)"
RUN echo "servertask present? $(if [ -f src/servertask/servertask ]; then echo yes; else echo no; fi)"

# ----------------------------
# Stage 2: Runtime image
# ----------------------------
FROM ubuntu:20.04

ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

# Runtime deps; include iproute2 for 'ss'
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      liblua5.1-0 ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Dirs
RUN mkdir -p /opt/conquest/data /opt/conquest/config /opt/conquest/defaults

# Binaries
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate /usr/local/bin/dgate
COPY --from=builder ${CONQUEST_SRC_DIR}/src/servertask/servertask /usr/local/bin/servertask

# Put defaults in a NON-mounted path
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.ini.default     /opt/conquest/defaults/dicom.ini.default
COPY --from=builder ${TEMP_CONFIG_DIR}/acrnema.map.default   /opt/conquest/defaults/acrnema.map.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dgatesop.lst.default  /opt/conquest/defaults/dgatesop.lst.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.sql.default     /opt/conquest/defaults/dicom.sql.default

# Dictionary (also as a default so volume doesn't mask it)
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate.dic            /opt/conquest/defaults/dgate.dic

# Bootstrap entrypoint: copy defaults into /opt/conquest/config if missing, then exec dgate from that dir
RUN printf '%s\n' \
'#!/bin/sh' \
'set -e' \
'CFG=/opt/conquest/config' \
'DEF=/opt/conquest/defaults' \
'mkdir -p "$CFG"' \
'[ -f "$CFG/dgate.dic" ]     || cp "$DEF/dgate.dic"              "$CFG/dgate.dic"' \
'[ -f "$CFG/dicom.ini" ]     || cp "$DEF/dicom.ini.default"      "$CFG/dicom.ini"' \
'[ -f "$CFG/acrnema.map" ]   || cp "$DEF/acrnema.map.default"    "$CFG/acrnema.map"' \
'[ -f "$CFG/dgatesop.lst" ]  || cp "$DEF/dgatesop.lst.default"   "$CFG/dgatesop.lst"' \
'[ -f "$CFG/dicom.sql" ]     || cp "$DEF/dicom.sql.default"      "$CFG/dicom.sql"' \
'echo "Using config dir: $CFG"; ls -l "$CFG" || true' \
'cd "$CFG"' \
'exec /usr/local/bin/dgate -v' \
> /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

# Keep your data dir as the workdir; we `cd` to CFG only for starting dgate
WORKDIR /opt/conquest/data
EXPOSE 5678

CMD ["/usr/local/bin/entrypoint.sh"]
