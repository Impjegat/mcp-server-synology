"""The autouse socket guard in conftest.py: it must keep every test from
reaching a real NAS, without breaking the machine-local sockets the runtime
itself needs."""

import asyncio
import socket

import pytest

from tests.socket_guard import is_local_address


@pytest.mark.parametrize(
    "address",
    [
        ("127.0.0.1", 5001),
        ("127.0.0.53", 5001),  # the whole 127.0.0.0/8 block is loopback
        ("::1", 5001, 0, 0),
        ("localhost", 5001),
        ("LOCALHOST", 5001),
        "/tmp/some.sock",  # AF_UNIX path
        b"\0abstract-socket",  # AF_UNIX abstract-namespace name
    ],
)
def test_local_addresses_are_recognised(address):
    assert is_local_address(address) is True


@pytest.mark.parametrize(
    "address",
    [
        ("192.168.1.100", 5001),
        ("203.0.113.5", 5001),
        ("nas.example.test", 5001),
        ("localhost.example.com", 5001),
        ("::ffff:203.0.113.5", 5001, 0, 0),  # IPv4-mapped, not loopback
        ("fe80::1%eth0", 5001, 0, 0),
        ("0.0.0.0", 5001),
        ("", 5001),
        (None, 5001),
        None,
        (),
        42,
    ],
)
def test_anything_not_positively_local_is_treated_as_remote(address):
    """The guard fails closed: an unparseable host or an unexpected address
    shape counts as remote."""
    assert is_local_address(address) is False


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_connecting_to_a_remote_address_is_blocked(method):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(RuntimeError, match="Outbound network access is blocked"):
            getattr(sock, method)(("203.0.113.5", 5001))


def test_an_http_request_is_blocked():
    import requests

    with pytest.raises(RuntimeError, match="Outbound network access is blocked"):
        requests.get("https://nas.example.test:5001/webapi/entry.cgi", timeout=1)


def test_an_http_request_cannot_tunnel_out_through_a_loopback_proxy():
    """Loopback sockets are allowed, and `requests` honors proxy settings —
    so without a block at the HTTP layer, an unmocked request would connect
    to a proxy on this machine and be carried out through it."""
    import requests

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fake_proxy:
        fake_proxy.bind(("127.0.0.1", 0))
        fake_proxy.listen(1)
        fake_proxy.settimeout(0.3)
        port = fake_proxy.getsockname()[1]

        with pytest.raises(RuntimeError, match="Outbound network access is blocked"):
            requests.get(
                "https://nas.example.test:5001/webapi/entry.cgi",
                proxies={"https": f"http://127.0.0.1:{port}"},
                timeout=1,
            )

        with pytest.raises(OSError):  # socket.timeout: nothing ever connected
            fake_proxy.accept()


def test_connecting_to_a_hostname_is_blocked_before_any_lookup():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(RuntimeError, match="Outbound network access is blocked"):
            sock.connect(("nas.example.test", 5001))


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_loopback_connections_still_work(method):
    """Windows' asyncio builds its event loop's self-pipe by connecting a
    socket to a loopback listener; blocking that failed every async test at
    setup, before it reached the code under test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            result = getattr(client, method)(listener.getsockname())
            assert result in (None, 0)  # connect() returns None, connect_ex() 0
            server_side, _ = listener.accept()
            server_side.close()


def test_ipv6_loopback_connections_still_work():
    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener.bind(("::1", 0))
    except OSError:
        pytest.skip("no usable IPv6 loopback on this machine")
    with listener:
        listener.listen(1)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
            client.connect(listener.getsockname())
            server_side, _ = listener.accept()
            server_side.close()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix-domain sockets here")
def test_unix_socket_connections_still_work(tmp_path):
    path = str(tmp_path / "s.sock")
    if len(path) > 100:
        pytest.skip("temp path too long for a Unix-domain socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(1)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(path)
            server_side, _ = listener.accept()
            server_side.close()


def test_asyncio_can_create_and_close_an_event_loop():
    """On Windows this is where the guard used to bite: creating the loop
    connects a loopback socket pair."""
    loop = asyncio.new_event_loop()
    loop.close()
