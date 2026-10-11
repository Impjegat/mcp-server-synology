"""Every DSM method the services call has been decided: a read, which may be
repeated once after a lost session is renewed, or a change, which never is.

`READ_ONLY_METHODS` is an allow-list, so a read that is missing from it is safe
(the caller is asked to run it again) but a nuisance, and nothing used to notice
one being added. This reads the service modules, collects every method name
they send, and fails when one has not been classified either way.
"""

import ast
import pathlib

from utils.synology_api import READ_ONLY_METHODS

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
SERVICES = ("filestation", "downloadstation", "container", "health", "nfs", "usermanagement")

# Methods that change something, or start something that does. `start` is a
# change for a delete or a move; a search's `start` is a read and is listed by
# API in `READ_ONLY_CALLS` (see tests/test_service_errors.py). `stop` and `status`
# on a task are not in the same position: `stop` ends a task (a change) and
# `status` only reads it.
CHANGES = frozenset(
    {
        "create",
        "delete",
        "join",
        "pause",
        "pull_start",
        "remove",
        "rename",
        "restart",
        "resume",
        "set",
        "set_by_user_group",
        "start",
        "stop",
        "update",
    }
)

# Where each service passes the method name to the request: the position of the
# argument for a call with that name.
_METHOD_ARGUMENT = {
    "_make_request": {"filestation": 2, "downloadstation": 2, "container": 2},
    "_container_name_request": {"container": 0},
}
_HELPERS_WITH_METHOD_SECOND = {"_api_call"}


def _string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _methods_called():
    """The literal method names each service sends, found by reading its code."""
    found = {}
    for service in SERVICES:
        names = found.setdefault(service, set())
        for path in (SRC / service).glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf8"))):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                name, args = node.func.attr, node.args
                if name in _METHOD_ARGUMENT:
                    position = _METHOD_ARGUMENT[name].get(service)
                elif name in _HELPERS_WITH_METHOD_SECOND or (
                    name in ("get", "post")
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "_api"
                ):
                    position = 1
                elif name == "_api_call_with_fallback":
                    for place in (1, 3):
                        method = _string(args[place]) if len(args) > place else None
                        if method:
                            names.add(method)
                    continue
                else:
                    continue
                if position is not None and len(args) > position:
                    method = _string(args[position])
                    if method:
                        names.add(method)
    return found


def test_the_scan_finds_the_calls_it_is_meant_to_classify():
    """A scan that quietly finds nothing would make every other test here pass."""
    found = _methods_called()
    assert all(found[service] for service in SERVICES), found
    assert {"rename", "start", "status"} <= found["filestation"]
    assert {"create", "delete", "pause", "resume", "getconfig"} <= found["downloadstation"]
    assert {"get", "list", "restart", "pull_start"} <= found["container"]


def test_every_method_the_services_send_is_classified_as_a_read_or_a_change():
    found = set().union(*_methods_called().values())
    unclassified = sorted(found - READ_ONLY_METHODS - CHANGES)
    assert not unclassified, (
        f"{unclassified} are sent to the NAS but are neither in READ_ONLY_METHODS "
        "(utils/synology_api.py) nor in CHANGES here. Decide which: a read may be "
        "repeated once after a lost session is renewed; a change never is."
    )


def test_nothing_is_in_both_lists():
    assert not READ_ONLY_METHODS & CHANGES


def test_no_list_holds_a_method_that_nothing_sends():
    """A typo in either list would otherwise go unnoticed."""
    found = set().union(*_methods_called().values())
    assert not sorted(READ_ONLY_METHODS - found), "READ_ONLY_METHODS names a method nobody sends"
    assert not sorted(CHANGES - found), "CHANGES names a method nobody sends"
