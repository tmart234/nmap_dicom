# Stage 1: Builder based on Ubuntu 20.04
FROM ubuntu:20.04 AS builder

ARG CONQUEST_GIT_REPO=https://github.com/marcelvanherk/Conquest-DICOM-Server.git
ARG CONQUEST_SRC_DIR=/build/Conquest-DICOM-Server

# Install build dependencies for Ubuntu 20.04
# *** MODIFIED: Added ca-certificates and combined update/install/clean ***
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
# *** END MODIFICATION ***

# Clone source code (This should work now)
RUN git clone ${CONQUEST_GIT_REPO} ${CONQUEST_SRC_DIR}
WORKDIR ${CONQUEST_SRC_DIR}

# Make scripts executable
RUN chmod +x linux/* src/servertask/make.sh install/maklinux install/makemak

# Compile dgate and servertask
RUN linux/maklinux_precompiled
RUN cd src/servertask && ./make.sh

# Stage 2: Runtime image (remains the same as previous example)
FROM ubuntu:20.04

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    liblua5.1-0 \
    # Add ca-certificates here too if dgate makes HTTPS calls? Unlikely but safe.
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/conquest/data /opt/conquest/config

# Copy compiled binaries from builder stage
COPY --from=builder /build/Conquest-DICOM-Server/dgate /usr/local/bin/dgate
COPY --from=builder /build/Conquest-DICOM-Server/src/servertask/servertask /usr/local/bin/servertask

# Copy default configuration files
COPY --from=builder /build/Conquest-DICOM-Server/dicom.ini /opt/conquest/config/dicom.ini.default
COPY --from=builder /build/Conquest-DICOM-Server/acrnema.map /opt/conquest/config/acrnema.map.default
# Add other necessary config files like dgatesop.lst, dicom.sql if needed by default operation
COPY --from=builder /build/Conquest-DICOM-Server/dgatesop.lst /opt/conquest/config/dgatesop.lst.default
COPY --from=builder /build/Conquest-DICOM-Server/dicom.sql /opt/conquest/config/dicom.sql.default


# Set workdir
WORKDIR /opt/conquest/data

# Expose default Conquest DICOM port
EXPOSE 5678

# Default command to run dgate
CMD ["/usr/local/bin/dgate", "-c", "/opt/conquest/config", "-v"]