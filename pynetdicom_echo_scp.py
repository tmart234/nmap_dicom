import sys
from pynetdicom import AE, evt
# Removed incorrect imports: AllStoragePresentationContexts, VerificationPresentationContexts
# Removed incorrect import: VerificationSOPClass

# Define the UID for the Verification SOP Class
VERIFICATION_SOP_CLASS_UID = '1.2.840.10008.1.1'

# Handler for evt.EVT_C_ECHO (remains the same)
def handle_echo(event):
    """Handle a C-ECHO request event."""
    print(f"Received C-ECHO request from {event.assoc.requestor.ae_title} on port {event.assoc.requestor.port}")
    # Return a 'Success' status
    return 0x0000

# Define the Application Entity (AE) (remains the same)
ae = AE(ae_title=b'PYNETDICOM') # Use bytes for AE Title

# --- CORRECTED WAY TO ADD CONTEXT ---
# Add supported presentation context for Verification SOP Class using its UID
ae.add_supported_context(VERIFICATION_SOP_CLASS_UID)
# ------------------------------------

# Define the handlers for specific events (remains the same)
handlers = [(evt.EVT_C_ECHO, handle_echo)]

# Start listening for associations (remains the same)
port = 11114 # Choose an internal port
print(f"Starting pynetdicom Echo SCP on port {port} with AE Title {ae.ae_title.decode()}")
try:
    # Blocking call until killed
    ae.start_server(('', port), block=True, evt_handlers=handlers)
except Exception as e:
     print(f"Error starting pynetdicom server: {e}")
     sys.exit(1)
except KeyboardInterrupt:
     print("Server stopped by user.")
     sys.exit(0)