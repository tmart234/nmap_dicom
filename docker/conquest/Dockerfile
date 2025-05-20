# Stage 1: Builder based on Ubuntu 20.04
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_REPO=https://github.com/marcelvanherk/Conquest-DICOM-Server.git
ARG CONQUEST_GIT_BRANCH=main # You can change this to a specific tag like v1.5.0e if preferred
ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server
ARG TEMP_CONFIG_DIR=/tmp_conquest_configs

# Install build dependencies (added curl)
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
RUN echo "Cloning Conquest DICOM Server binaries' source from ${CONQUEST_GIT_REPO} branch ${CONQUEST_GIT_BRANCH} into ${CONQUEST_SRC_DIR}"
RUN git clone --depth 1 --branch ${CONQUEST_GIT_BRANCH} ${CONQUEST_GIT_REPO} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}

# --- Diagnostic: List files immediately after clone (for src, linux dirs mainly now) ---
RUN echo "--- Listing contents of ${CONQUEST_SRC_DIR} (root) immediately after git clone ---" && ls -lA ./

# --- Fetch config files directly using curl to TEMP_CONFIG_DIR ---
RUN echo "Creating temporary config directory: ${TEMP_CONFIG_DIR}" && mkdir -p ${TEMP_CONFIG_DIR}
RUN echo "Fetching config files directly to ${TEMP_CONFIG_DIR} using curl from branch ${CONQUEST_GIT_BRANCH}"

# Define config files to download
ARG DICOM_INI=dicom.ini
ARG ACRNEMA_MAP=acrnema.map
ARG DGATESOP_LST=dgatesop.lst
ARG DICOM_SQL=dicom.sql

RUN curl -sfL "${CONQUEST_GIT_REPO}/raw/${CONQUEST_GIT_BRANCH}/${DICOM_INI}" -o "${TEMP_CONFIG_DIR}/${DICOM_INI}.default" \
    || (echo "ERROR: Failed to download ${DICOM_INI}" && exit 1)
RUN curl -sfL "${CONQUEST_GIT_REPO}/raw/${CONQUEST_GIT_BRANCH}/${ACRNEMA_MAP}" -o "${TEMP_CONFIG_DIR}/${ACRNEMA_MAP}.default" \
    || (echo "ERROR: Failed to download ${ACRNEMA_MAP}" && exit 1)
RUN curl -sfL "${CONQUEST_GIT_REPO}/raw/${CONQUEST_GIT_BRANCH}/${DGATESOP_LST}" -o "${TEMP_CONFIG_DIR}/${DGATESOP_LST}.default" \
    || (echo "ERROR: Failed to download ${DGATESOP_LST}" && exit 1)
RUN curl -sfL "${CONQUEST_GIT_REPO}/raw/${CONQUEST_GIT_BRANCH}/${DICOM_SQL}" -o "${TEMP_CONFIG_DIR}/${DICOM_SQL}.default" \
    || (echo "ERROR: Failed to download ${DICOM_SQL}" && exit 1)

RUN echo "--- Listing contents of ${TEMP_CONFIG_DIR} after direct fetch ---" && ls -lA ${TEMP_CONFIG_DIR}
RUN echo "Checking for ${TEMP_CONFIG_DIR}/${DICOM_INI}.default: $(if [ -f ${TEMP_CONFIG_DIR}/${DICOM_INI}.default ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"

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


# Stage 2: Runtime image (This part remains mostly the same)
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

# Copy compiled binaries from builder stage (Paths relative to CONQUEST_SRC_DIR in builder)
COPY --from=builder ${CONQUEST_SRC_DIR}/dgate /usr/local/bin/dgate
COPY --from=builder ${CONQUEST_SRC_DIR}/src/servertask/servertask /usr/local/bin/servertask

# Copy default configuration files FROM THE TEMP_CONFIG_DIR (where curl downloaded them)
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.ini.default /opt/conquest/config/dicom.ini.default
COPY --from=builder ${TEMP_CONFIG_DIR}/acrnema.map.default /opt/conquest/config/acrnema.map.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dgatesop.lst.default /opt/conquest/config/dgatesop.lst.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.sql.default /opt/conquest/config/dicom.sql.default

# Set workdir
WORKDIR /opt/conquest/data

# Expose default Conquest DICOM port
EXPOSE 5678

CMD ["/usr/local/bin/dgate", "-c", "/opt/conquest/config", "-v"]