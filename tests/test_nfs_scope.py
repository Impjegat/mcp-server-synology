"""NFS share discovery is limited to the folders a client may reach.

`synology_nfs_list_shares` is in a broker client's default tools, and it returns
every share on the NAS with its NFS client and permission rules. It must show a
client only the shares its folder policy reaches, and nothing about the others
(implementation review R07). Every NAS answer here is a fake.
"""

import json
from unittest.mock import patch

import pytest

from nfs.synology_nfs import SynologyNFS
from tests.broker_support import BASE_URLS, Broker

CLIENTS = {
    "alice": {"nas": ["nas1"], "folders": {"nas1": ["/docs"]}},
    "bob": {"nas": ["nas1"], "folders": {"nas1": ["/photos/2026"]}},
    "carol": {"nas": ["nas1"]},  # no folder at all
    # A folder whose name the policy always refuses, next to an ordinary one.
    "dave": {"nas": ["nas1"], "folders": {"nas1": ["/secrets", "/docs"]}},
}

_DEFAULT = object()


def _share(name, client):
    return {
        "name": name,
        "vol_path": "/volume1",
        "desc": f"the {name} share",
        "additional": {"nfs_privilege": [{"client": client, "privilege": "rw"}]},
    }


def _discovery():
    return {
        "success": True,
        "data": {
            "offset": 0,
            "total": 6,
            "shares": [
                _share("docs", "192.168.1.10"),
                _share("music", "192.168.9.9"),
                _share("photos", "10.9.8.7"),
                _share("secrets", "172.16.5.5"),
                _share("docs2", "172.20.1.1"),
                _share("Docs", "172.21.2.2"),
            ],
        },
    }


@pytest.fixture
def broker(monkeypatch):
    broker = Broker(monkeypatch, CLIENTS)
    for client in CLIENTS:
        broker.sign_in(client)
    return broker


async def _list(broker, client, reply=_DEFAULT):
    reply = _discovery() if reply is _DEFAULT else reply
    with patch.object(SynologyNFS, "list_shares", return_value=reply):
        return await broker.runtime.call_tool(
            client, "synology_nfs_list_shares", {"nas_name": "nas1"}
        )


def _data(result):
    assert result.is_error is False, result.content[0].text
    return json.loads(result.content[0].text)["data"]


def _text(result):
    return result.content[0].text


class TestADiscoveryIsScopedToTheClientsFolders:
    @pytest.mark.asyncio
    async def test_r07_a_client_sees_only_the_share_its_folder_is_in(self, broker):
        data = _data(await _list(broker, "alice"))
        assert [s["name"] for s in data["shares"]] == ["docs"]
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_r07_nothing_about_the_other_shares_is_returned(self, broker):
        text = _text(await _list(broker, "alice"))
        for other in ("music", "photos", "secrets", "docs2", "Docs"):
            assert f'"{other}"' not in text
        for marker in ("192.168.9.9", "10.9.8.7", "172.16.5.5", "172.20.1.1", "172.21.2.2"):
            assert marker not in text

    @pytest.mark.asyncio
    async def test_a_share_inside_the_scope_keeps_its_nfs_rules(self, broker):
        (share,) = _data(await _list(broker, "alice"))["shares"]
        assert share["additional"]["nfs_privilege"][0]["client"] == "192.168.1.10"
        assert share["vol_path"] == "/volume1"

    @pytest.mark.asyncio
    async def test_r07_a_share_that_only_holds_the_clients_folder_is_named_and_nothing_more(
        self, broker
    ):
        """bob may reach /photos/2026, not the whole of /photos: its NFS rules say
        who may mount all of it, which is not his to know."""
        data = _data(await _list(broker, "bob"))
        assert data["shares"] == [{"name": "photos"}]
        assert "10.9.8.7" not in json.dumps(data)

    @pytest.mark.asyncio
    async def test_r07_a_client_with_no_folder_discovers_no_share(self, broker):
        data = _data(await _list(broker, "carol"))
        assert data["shares"] == [] and data["total"] == 0

    @pytest.mark.asyncio
    async def test_a_share_with_a_name_the_policy_always_refuses_is_never_shown(self, broker):
        """dave's own folder list names /secrets; the policy refuses that name
        wherever it is, so its NFS rules are not shown either."""
        data = _data(await _list(broker, "dave"))
        assert [s["name"] for s in data["shares"]] == ["docs"]
        assert "172.16.5.5" not in json.dumps(data)

    @pytest.mark.asyncio
    async def test_other_fields_of_the_answer_are_kept(self, broker):
        assert _data(await _list(broker, "alice"))["offset"] == 0

    @pytest.mark.asyncio
    async def test_r07_an_entry_that_cannot_be_judged_is_dropped(self, broker):
        reply = _discovery()
        reply["data"]["shares"] += [
            "not-an-object",
            {"vol_path": "/volume1"},  # no name
            {"name": ""},
            {"name": 5},
            {"name": "docs/../music"},  # a name that would read as another path
            {"name": "x/../docs"},  # one that would read as an allowed share
            {"name": "docs\\x"},
        ]
        data = _data(await _list(broker, "alice", reply))
        assert [s["name"] for s in data["shares"]] == ["docs"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "reply",
        [
            {"success": True},
            {"success": True, "data": "oops"},
            {"success": True, "data": {"shares": "oops"}},
            {"success": True, "data": {"total": 3}},
            {"success": True, "data": ["docs"]},
            # Not even an object: nothing to filter, so nothing is passed on.
            None,
            [],
            "docs",
            ["docs", "music"],
        ],
    )
    async def test_r07_an_answer_in_a_shape_that_is_not_understood_is_refused_not_passed_on(
        self, broker, reply
    ):
        result = await _list(broker, "alice", reply)
        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_a_failure_from_the_nas_is_still_a_failure(self, broker):
        failure = {"success": False, "error": {"code": 105}}
        result = await _list(broker, "alice", failure)
        assert result.is_error is True
        assert '"code": 105' in _text(result)

    @pytest.mark.asyncio
    async def test_the_nfs_service_status_is_not_share_specific_and_is_unchanged(self, broker):
        status = {"success": True, "data": {"enable_nfs": True, "nfs4_enable": False}}
        with patch.object(SynologyNFS, "nfs_status", return_value=status):
            result = await broker.runtime.call_tool(
                "alice", "synology_nfs_status", {"nas_name": "nas1"}
            )
        assert json.loads(_text(result)) == status


class TestWithoutAFolderPolicyNothingIsFiltered:
    """Legacy mode has no folder policy; its discovery is as it always was."""

    @pytest.mark.asyncio
    async def test_every_share_is_returned(self):
        from mcp_server import SynologyMCPServer

        server = SynologyMCPServer()
        with (
            patch.object(server, "_get_base_url", return_value=BASE_URLS["nas1"]),
            patch.object(
                server,
                "_get_nfs",
                return_value=type("N", (), {"list_shares": lambda s: _discovery()})(),
            ),
        ):
            result = await server._handle_nfs_call({}, "list_shares")
        data = json.loads(result[0].text)["data"]
        assert len(data["shares"]) == 6 and data["total"] == 6
