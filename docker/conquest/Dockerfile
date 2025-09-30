# Stage 1: Builder based on Ubuntu 20.04
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_USER=marcelvanherk
ARG CONQUEST_GIT_PROJECT_NAME=Conquest-DICOM-Server
ARG CONQUEST_GIT_REPO_URL=https://github.com/${CONQUEST_GIT_USER}/${CONQUEST_GIT_PROJECT_NAME}.git # Used for git clone
ARG CONQUEST_GIT_BRANCH=master
ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    make \
    g++ \
    lua5.1 \
    liblua5.1-0-dev \
    gettext-base \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Clone source code for building binaries (dgate, servertask)
# This step seems to get the necessary src/ and linux/ directories for compilation
RUN echo "Cloning Conquest DICOM Server's source from ${CONQUEST_GIT_REPO_URL} branch ${CONQUEST_GIT_BRANCH} into ${CONQUEST_SRC_DIR}"
RUN git clone --depth 1 --branch ${CONQUEST_GIT_BRANCH} ${CONQUEST_GIT_REPO_URL} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}

# --- Diagnostic: List files immediately after clone ---
RUN echo "--- Listing contents of ${CONQUEST_SRC_DIR} (root) immediately after git clone ---" && ls -lA ./

# --- Fetch config files directly using curl to TEMP_CONFIG_DIR ---
RUN echo "Creating temporary config directory: ${TEMP_CONFIG_DIR}" && mkdir -p ${TEMP_CONFIG_DIR}
RUN echo "Fetching config files directly to ${TEMP_CONFIG_DIR} using curl from branch ${CONQUEST_GIT_BRANCH}"

# Define config files we want to stage as defaults
ARG DICOM_INI=dicom.ini
ARG ACRNEMA_MAP=acrnema.map
ARG DGATESOP_LST=dgatesop.lst
ARG DICOM_SQL=dicom.sql

# Copy defaults directly from the cloned repo instead of raw.githubusercontent.com
RUN echo "Staging default configs from ${CONQUEST_SRC_DIR} into ${TEMP_CONFIG_DIR}" && \
    cp -v "${CONQUEST_SRC_DIR}/${DICOM_INI}"    "${TEMP_CONFIG_DIR}/${DICOM_INI}.default"    || true && \
    cp -v "${CONQUEST_SRC_DIR}/${ACRNEMA_MAP}"  "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default" || true && \
    cp -v "${CONQUEST_SRC_DIR}/${DGATESOP_LST}" "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default"|| true && \
    cp -v "${CONQUEST_SRC_DIR}/${DICOM_SQL}"    "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default"    || true && \
    echo "--- Listing contents of ${TEMP_CONFIG_DIR} ---" && ls -lA "${TEMP_CONFIG_DIR}" && \
    if [ -f "${TEMP_CONFIG_DIR}/${DICOM_INI}.default" ]; then echo "dicom.ini.default: Found"; else echo "dicom.ini.default: NOT FOUND"; fi

# Make build scripts executable (these should be from the git clone)
RUN chmod +x linux/maklinux_precompiled src/servertask/make.sh

# Compile dgate and servertask
RUN echo "Running linux/maklinux_precompiled..."
RUN linux/maklinux_precompiled
RUN echo "Running make.sh in src/servertask..."
RUN cd src/servertask && ./make.sh

# --- Diagnostic: List files AFTER build scripts (in cloned directory) ---
RUN echo "--- Listing contents of ${CONQUEST_SRC_DIR} (root) AFTER build scripts ---" && ls -lA ./
RUN echo "Checking for dgate executable: $(if [ -f dgate ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"
RUN echo "Checking for servertask executable: $(if [ -f src/servertask/servertask ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"


# Stage 2: Runtime image
FROM ubuntu:20.04

ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    liblua5.1-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories for Conquest
RUN mkdir -p /opt/conquest/data /opt/conquest/config

# Copy compiled binaries from builder stage
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate /usr/local/bin/dgate
COPY --from=builder ${CONQUEST_SRC_DIR}/src/servertask/servertask /usr/local/bin/servertask

# Copy default configuration files staged in the builder
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.ini.default     /opt/conquest/config/dicom.ini.default
COPY --from=builder ${TEMP_CONFIG_DIR}/acrnema.map.default   /opt/conquest/config/acrnema.map.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dgatesop.lst.default  /opt/conquest/config/dgatesop.lst.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.sql.default     /opt/conquest/config/dicom.sql.default

# Dictionary needed by Conquest
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate.dic /opt/conquest/config/dgate.dic

# Bootstrap entrypoint: populate missing configs then exec dgate
RUN printf '%s\n' \
'#!/bin/sh' \
'set -e' \
'CFG=/opt/conquest/config' \
'[ -f "$CFG/dicom.ini" ]    || cp "$CFG/dicom.ini.default"    "$CFG/dicom.ini"' \
'[ -f "$CFG/acrnema.map" ]  || cp "$CFG/acrnema.map.default"  "$CFG/acrnema.map"' \
'[ -f "$CFG/dgatesop.lst" ] || cp "$CFG/dgatesop.lst.default" "$CFG/dgatesop.lst"' \
'[ -f "$CFG/dicom.sql" ]    || cp "$CFG/dicom.sql.default"    "$CFG/dicom.sql"' \
'exec /usr/local/bin/dgate -c "$CFG" -v' \
> /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt/conquest/data

EXPOSE 5678

# Only ONE CMD in this stage
CMD ["/usr/local/bin/entrypoint.sh"]