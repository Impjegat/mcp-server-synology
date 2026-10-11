"""Container health check for the broker: is it up and ready to take requests?

Asks the broker's own /readyz over loopback and exits 0 only on a 200. The
endpoint says nothing about the NAS, the clients or any session, and a broker
nobody has signed in to is ready, not unhealthy, so this cannot be used to learn
anything about who is signed in. It does not verify the certificate: it talks to
the process in its own container over loopback, and verifying would need the
certificate to name 127.0.0.1.

BROKER_HEALTH_URL overrides the address (the default is the broker's own MCP port
inside the container).
"""

import os
import ssl
import sys
import urllib.request

URL = os.environ.get("BROKER_HEALTH_URL", "https://127.0.0.1:8443/readyz")


def main() -> int:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(URL, timeout=4, context=context) as response:
            return 0 if response.status == 200 else 1
    except Exception:  # any failure is "not healthy"; the reason is not needed here
        return 1


if __name__ == "__main__":
    sys.exit(main())
