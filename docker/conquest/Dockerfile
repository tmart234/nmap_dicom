# Stage 1: Builder based on a slightly older but stable build environment
# Using 20.04 as 14.04 is EOL and 22.04 might introduce too many changes at once
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_REPO=https://github.com/marcelvanherk/Conquest-DICOM-Server.git
ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server

# Install build dependencies for Ubuntu 20.04
# Check prebuild/Dockerfile for hints, adjust package names as needed
# lua5.1-dev includes headers needed for linking usually
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    make \
    g++ \
    lua5.1 \
    liblua5.1-0-dev \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Clone source code
RUN git clone ${CONQUEST_GIT_REPO} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}

# Make scripts executable (adjust paths/scripts based on actual repo structure if needed)
RUN chmod +x linux/* src/servertask/make.sh install/maklinux install/makemak

# Compile dgate and servertask (using precompiled libs approach from official repo)
# Ensure the paths inside maklinux_precompiled are correct relative to WORKDIR
RUN linux/maklinux_precompiled
RUN cd src/servertask && ./make.sh

# Stage 2: Runtime image based on a modern Ubuntu
FROM ubuntu:20.04

# Install runtime dependencies (likely just liblua)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    liblua5.1-0 \
    # Add any other runtime libs identified via ldd if needed
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/conquest/data /opt/conquest/config

# Copy compiled binaries from builder stage
COPY --from=builder /build/Conquest-DICOM-Server/dgate /usr/local/bin/dgate
COPY --from=builder /build/Conquest-DICOM-Server/src/servertask/servertask /usr/local/bin/servertask

# Copy default configuration files (adjust source paths if needed)
# It's better to mount config via volumes in compose, but copy defaults
COPY --from=builder /build/Conquest-DICOM-Server/dicom.ini /opt/conquest/config/dicom.ini.default
COPY --from=builder /build/Conquest-DICOM-Server/acrnema.map /opt/conquest/config/acrnema.map.default
# You might need other files like dgatesop.lst depending on config

# Set workdir
WORKDIR /opt/conquest/data

# Expose default Conquest DICOM port
EXPOSE 5678

# Default command to run dgate
# -c points to the directory containing dicom.ini
# -v for verbose logging
# Mount /opt/conquest/config and /opt/conquest/data as volumes in docker-compose
CMD ["/usr/local/bin/dgate", "-c", "/opt/conquest/config", "-v"]