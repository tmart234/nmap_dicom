#!/bin/bash
# Script to test the DICOM version detection against multiple servers

# Define ports used on the HOST machine
ORTHANC_HOST_PORT=11112
DCM4CHEE_HOST_PORT=11113

# Start the DICOM servers
echo "Starting DICOM servers (Orthanc, DCM4CHEE)..."
# Use --detach (-d) and --wait for docker compose v2+ to wait for containers to be healthy/running
# Fallback to sleep if --wait is not available or healthchecks aren't reliable enough
docker-compose up -d --remove-orphans # Start services in detached mode

# Wait for servers to initialize
# Using sleep is simpler than relying on potentially complex healthchecks across different images
INITIALIZATION_TIME=30 # Increased wait time as dcm4chee might take longer
echo "Waiting for servers to initialize (${INITIALIZATION_TIME} seconds)..."
sleep ${INITIALIZATION_TIME}

# --- Test Orthanc ---
echo -e "\n--- Testing Orthanc DICOM server on host port $ORTHANC_HOST_PORT ---"
nmap -p $ORTHANC_HOST_PORT -d --script="dicom-ping.nse" --script-trace localhost

# Show Orthanc logs briefly
echo -e "\n--- Orthanc server logs (Tail) ---"
docker-compose logs --tail="20" orthanc

# --- Test DCM4CHEE ---
echo -e "\n--- Testing DCM4CHEE DICOM server on host port $DCM4CHEE_HOST_PORT ---"
# Note: DCM4CHEE might require specific AE Titles. Default is 'DCM4CHEE'.
# Our script uses ECHOSCU -> ANY-SCP by default. This might fail association if DCM4CHEE enforces AE titles.
# If it fails, try overriding with script-args:
# nmap -p $DCM4CHEE_HOST_PORT -d --script="dicom-ping.nse" --script-args dicom.called_aet=DCM4CHEE,dicom.calling_aet=ECHOSCU --script-trace localhost
nmap -p $DCM4CHEE_HOST_PORT -d --script="dicom-ping.nse" --script-trace localhost

# Show DCM4CHEE logs briefly
echo -e "\n--- DCM4CHEE server logs (Tail) ---"
docker-compose logs --tail="20" dcm4chee


# --- Optional: Show logs with DICOM mentions ---
echo -e "\n--- Orthanc server logs (DICOM Filter) ---"
docker-compose logs orthanc | grep -A 5 -B 5 "DICOM" || echo "No DICOM mentions found in Orthanc logs."

echo -e "\n--- DCM4CHEE server logs (DICOM Filter) ---"
# DCM4CHEE logs might use different keywords, adjust grep if needed
docker-compose logs dcm4chee | grep -A 5 -B 5 -E "DICOM|DIMSE|Association" || echo "No DICOM/Association mentions found in DCM4CHEE logs."


# Cleanup
echo -e "\nShutting down DICOM servers..."
docker-compose down --volumes # Also remove associated volumes like orthanc_db

echo "Test script finished."