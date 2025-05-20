# Stage 1: Builder based on Ubuntu 20.04
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_REPO=https://github.com/marcelvanherk/Conquest-DICOM-Server.git
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
    && rm -rf /var/lib/apt/lists/*

# Clone source code
RUN echo "Cloning Conquest DICOM Server from ${CONQUEST_GIT_REPO} into ${CONQUEST_SRC_DIR}"
RUN git clone --depth 1 ${CONQUEST_GIT_REPO} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}

# --- Diagnostic: List files immediately after clone ---
RUN echo "--- Listing contents of ${CONQUEST_SRC_DIR} (root) immediately after clone ---" && ls -lA ./
RUN echo "Checking for dicom.ini: $(if [ -f dicom.ini ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"
RUN echo "Checking for acrnema.map: $(if [ -f acrnema.map ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"
RUN echo "Checking for dgatesop.lst: $(if [ -f dgatesop.lst ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"
RUN echo "Checking for dicom.sql: $(if [ -f dicom.sql ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"

# --- Safe copy of configuration files ---
RUN echo "Creating temporary config directory: ${TEMP_CONFIG_DIR}" && mkdir -p ${TEMP_CONFIG_DIR}
RUN echo "Copying config files to ${TEMP_CONFIG_DIR}"
# Use find to safely copy only if they exist, preventing errors if a file is missing
RUN find . -maxdepth 1 -name 'dicom.ini' -exec cp {} ${TEMP_CONFIG_DIR}/dicom.ini.default \; || echo "dicom.ini not found for safe copy"
RUN find . -maxdepth 1 -name 'acrnema.map' -exec cp {} ${TEMP_CONFIG_DIR}/acrnema.map.default \; || echo "acrnema.map not found for safe copy"
RUN find . -maxdepth 1 -name 'dgatesop.lst' -exec cp {} ${TEMP_CONFIG_DIR}/dgatesop.lst.default \; || echo "dgatesop.lst not found for safe copy"
RUN find . -maxdepth 1 -name 'dicom.sql' -exec cp {} ${TEMP_CONFIG_DIR}/dicom.sql.default \; || echo "dicom.sql not found for safe copy"
RUN echo "--- Listing contents of ${TEMP_CONFIG_DIR} after safe copy ---" && ls -lA ${TEMP_CONFIG_DIR}

# Make build scripts executable
RUN chmod +x linux/maklinux_precompiled src/servertask/make.sh

# Compile dgate and servertask
RUN echo "Running linux/maklinux_precompiled..."
RUN linux/maklinux_precompiled
RUN echo "Running make.sh in src/servertask..."
RUN cd src/servertask && ./make.sh

# --- Diagnostic: List files AFTER build scripts ---
RUN echo "--- Listing contents of ${CONQUEST_SRC_DIR} (root) AFTER build scripts ---" && ls -lA ./
RUN echo "Checking for dicom.ini post-build: $(if [ -f dicom.ini ]; then echo 'Found'; else echo 'NOT FOUND'; fi)"
RUN echo "--- Listing contents of /build/Conquest-DICOM-Server (the ARG value) for final verification ---" && ls -lA ${CONQUEST_SRC_DIR}/


# Stage 2: Runtime image
FROM ubuntu:20.04

# ARG for runtime (if needed, but paths from builder are absolute)
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

# Copy default configuration files FROM THE SAFE LOCATION in the builder stage
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.ini.default /opt/conquest/config/dicom.ini.default
COPY --from=builder ${TEMP_CONFIG_DIR}/acrnema.map.default /opt/conquest/config/acrnema.map.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dgatesop.lst.default /opt/conquest/config/dgatesop.lst.default
COPY --from=builder ${TEMP_CONFIG_DIR}/dicom.sql.default /opt/conquest/config/dicom.sql.default

# Set workdir
WORKDIR /opt/conquest/data

# Expose default Conquest DICOM port
EXPOSE 5678

# Default command to run dgate
# Ensure the config directory points to where the .default files are, or where user-mounted configs will be.
# The application will likely copy .default to active files on first run if they don't exist.
CMD ["/usr/local/bin/dgate", "-c", "/opt/conquest/config", "-v"]