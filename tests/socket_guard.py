"""Address classification for the socket guard in conftest.py, kept in its
own module so the guard's tests can import it (conftest itself isn't
importable by name from a test module)."""

import ipaddress


def is_local_address(address) -> bool:
    """True if `address` (as passed to socket.connect) stays on this machine:
    a loopback IP, `localhost`, or a Unix-domain socket path.

    Anything that can't be positively identified as local — an unparseable
    host, an unexpected address shape — is treated as remote, so the guard
    fails closed.
    """
    # AF_UNIX: the address is a filesystem path (str/bytes), not a tuple.
    if isinstance(address, (str, bytes)):
        return True
    try:
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("ascii")
        if host.lower() == "localhost":
            return True
        # An IPv6 literal may carry a zone ("fe80::1%eth0"); loopback has none.
        return ipaddress.ip_address(host).is_loopback
    except Exception:
        return False
