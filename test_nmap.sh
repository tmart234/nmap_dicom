#!/bin/bash
# Script to test the DICOM version detection
# place in the nmap directory

# Get the current directory
SCRIPT_DIR="$(pwd)/scripts/"
PORT=11112
echo "Script dir is: $SCRIPT_DIR and port is: $PORT"

# Start the Orthanc container
echo "Starting Orthanc DICOM server..."
docker-compose up -d

# Wait for Orthanc to initialize
echo "Waiting for Orthanc to initialize (15 seconds)..."
sleep 15

# Test using the host-mapped port
# Since were using port forwarding in the Docker Compose setup (4242:4242), 
#   scanning localhost:4242 will reach the containers DICOM service, 
#   eliminating the need to scan against the container's IP address.
echo -e "\nTesting DICOM server on host port $PORT..."
nmap -p $PORT -d --script="$SCRIPT_DIR/dicom-ping.nse" --script-trace localhost

# Show Orthanc logs
echo -e "\nOrthanc server logs:"
docker-compose logs orthanc | tail -n 20

# Show Orthanc logs and see if any DICOM connections were made
echo -e "\nOrthanc server logs:"
docker-compose logs orthanc | grep -A 5 -B 5 "DICOM"

# Cleanup
echo -e "\nShutting down Orthanc..."
docker-compose down
