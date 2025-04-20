import sys
from pynetdicom import AE, evt, AllStoragePresentationContexts, VerificationPresentationContexts
from pynetdicom.sop_class import VerificationSOPClass

# Handler for evt.EVT_C_ECHO
def handle_echo(event):
    """Handle a C-ECHO request event."""
    print(f"Received C-ECHO request from {event.assoc.requestor.ae_title} on port {event.assoc.requestor.port}")
    # Return a 'Success' status
    return 0x0000

# Define the Application Entity (AE)
ae = AE(ae_title=b'PYNETDICOM') # Use bytes for AE Title

# Add supported presentation contexts (Verification is needed for C-ECHO)
ae.add_supported_context(VerificationSOPClass)
# Optionally add storage contexts if you wanted to handle C-STORE later
# for context in AllStoragePresentationContexts:
#    ae.add_supported_context(context.abstract_syntax, context.transfer_syntax)

# Define the handlers for specific events
handlers = [(evt.EVT_C_ECHO, handle_echo)]

# Start listening for associations
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