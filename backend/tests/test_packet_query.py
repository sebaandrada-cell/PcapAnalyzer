"""POST /sessions/{id}/packets: real Wireshark display filters over the whole capture."""
from __future__ import annotations

import pytest

from app import config
from app.tshark import find_tshark
from tests.test_capture_quality import healthy_flows, mirrored, write_packets

pytestmark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")


def _session(client, path):
    r = client.post("/analyze", files={"file": (path.name, path.read_bytes(),
                                                "application/octet-stream")})
    assert r.status_code == 200, r.text
    return r.json()


def _query(client, sid, **body):
    return client.post("/sessions/%s/packets" % sid, json=body)


@pytest.fixture
def big(client, tmp_path, monkeypatch):
    """A capture larger than the packet-list sample (the sample holds 20 rows)."""
    monkeypatch.setattr(config, "PACKET_LIST_MAX", 20)
    path = tmp_path / "big.pcap"
    write_packets(path, healthy_flows(n_flows=8))  # 208 packets
    result = _session(client, path)
    assert result["packet_list"]["truncated"] and len(result["packet_list"]["rows"]) == 20
    return result


def test_filter_reaches_packets_beyond_the_sample(client, big):
    sid = big["session"]["id"]

    r = _query(client, sid, filter="frame.number == 150")

    assert r.status_code == 200
    body = r.json()
    assert [row["number"] for row in body["rows"]] == [150]
    assert body["has_more"] is False and body["matched"] == 1
    row = body["rows"][0]
    assert {"time", "src", "dst", "protocol", "length", "info", "stream", "tcp_flags"} <= set(row)
    assert row["src"].startswith("10.") and row["time"] > 0


def test_rows_have_the_same_shape_as_the_packet_list(client, sample_pcap):
    result = _session(client, sample_pcap)
    by_number = {row["number"]: row for row in result["packet_list"]["rows"]}

    body = _query(client, result["session"]["id"], filter="tcp.flags.reset == 1").json()

    assert body["rows"] and all("RST" in row["tcp_flags"] for row in body["rows"])
    for row in body["rows"]:
        assert row == by_number[row["number"]]


def test_paging(client, big):
    sid = big["session"]["id"]

    first = _query(client, sid, filter="tcp.flags.syn == 1", limit=5).json()
    second = _query(client, sid, filter="tcp.flags.syn == 1", limit=5, offset=5).json()

    assert len(first["rows"]) == 5 and first["has_more"] is True and first["matched"] is None
    assert second["rows"][0]["number"] > first["rows"][-1]["number"]
    assert second["offset"] == 5
    everything = _query(client, sid, filter="tcp.flags.syn == 1", limit=1000).json()
    assert everything["matched"] == 16 and everything["has_more"] is False  # 8 SYN + 8 SYN-ACK


def test_empty_filter_returns_the_first_packets(client, big):
    body = _query(client, big["session"]["id"], filter="  ", limit=30).json()

    assert [row["number"] for row in body["rows"]] == list(range(1, 31))
    assert body["has_more"] is True


def test_invalid_filter_is_a_422_with_tsharks_reason(client, big):
    r = _query(client, big["session"]["id"], filter="tcp.port ==")

    assert r.status_code == 422
    assert "Filtro no válido" in r.json()["detail"]


def test_limits_are_validated(client, big):
    sid = big["session"]["id"]
    assert _query(client, sid, filter="tcp", limit=5000).status_code == 422
    assert _query(client, sid, filter="x" * 2001).status_code == 422
    assert _query(client, sid, filter="tcp\n-r /etc/passwd").status_code == 422


def test_unknown_and_foreign_sessions_are_404(client, big, monkeypatch):
    assert _query(client, "nope", filter="tcp").status_code == 404
    monkeypatch.setattr(config, "API_TOKENS", ["test-token", "other"])
    r = client.post("/sessions/%s/packets" % big["session"]["id"], json={"filter": "tcp"},
                    headers={"Authorization": "Bearer other"})
    assert r.status_code == 404


def test_duplicated_frames_keep_their_mark(client, tmp_path):
    path = tmp_path / "mirror.pcap"
    write_packets(path, mirrored(healthy_flows(n_flows=2)))
    sid = _session(client, path)["session"]["id"]

    rows = _query(client, sid, filter="tcp.stream eq 0", limit=1000).json()["rows"]

    marked = [row for row in rows if row["analysis"] == ["duplicate_frame"]]
    assert len(marked) == len(rows) // 2
    assert all("retransmission" not in row["analysis"] for row in rows)


def test_busy_server_answers_429(client, big):
    from app.agent import router

    assert router._packet_queries.acquire(blocking=False)
    try:
        while router._packet_queries.acquire(blocking=False):
            pass
        r = _query(client, big["session"]["id"], filter="tcp")
    finally:
        for _ in range(max(1, config.PACKET_QUERY_WORKERS)):
            try:
                router._packet_queries.release()
            except ValueError:
                break
    assert r.status_code == 429
