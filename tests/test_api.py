"""End-to-end API tests via FastAPI's TestClient."""

import copy

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


DOC = {
    "issuer": "https://id.example",
    "subject": {
        "id": "u-123",
        "name": "Ada Lovelace",
        "age": 36,
        "isAdult": True,
        "nickname": None,
    },
    "emails": ["ada@example.com", "ada@analytical.engine"],
    "emptyObj": {},
    "emptyArr": [],
    "deep": {"a/b": {"tilde~key": [7]}},
}


def _commit(reveal):
    return client.post("/commit", json={"document": DOC, "reveal": reveal})


def test_health_and_index():
    assert client.get("/healthz").json() == {"status": "ok"}
    info = client.get("/").json()
    assert info["hash"] == "sha256"


def test_commit_verify_roundtrip_single_and_multiple():
    resp = _commit(["/subject/age", "/emails/1", "/emptyObj", "/emptyArr"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["leaves"]) == 4
    values = {leaf["path"]: leaf["value"] for leaf in data["leaves"]}
    assert values == {
        "/subject/age": 36,
        "/emails/1": "ada@analytical.engine",
        "/emptyObj": {},
        "/emptyArr": [],
    }
    # Response only contains the selected values plus proofs.
    for leaf in data["leaves"]:
        assert set(leaf.keys()) == {"path", "value", "proof"}

    verify = client.post(
        "/verify", json={"root": data["root"], "leaves": data["leaves"]}
    )
    assert verify.status_code == 200, verify.text
    body = verify.json()
    assert body["valid"] is True
    assert body["root"] == data["root"]
    assert [leaf["path"] for leaf in body["leaves"]] == sorted(
        leaf["path"] for leaf in data["leaves"]
    )


def test_root_is_reproducible_and_independent_of_reveal():
    r1 = _commit(["/issuer"]).json()["root"]
    r2 = _commit(["/subject/name", "/emails/0"]).json()["root"]
    # Same document -> identical root regardless of which paths are selected.
    assert r1 == r2
    # Different document -> different root.
    changed = copy.deepcopy(DOC)
    changed["subject"]["age"] = 37
    r3 = client.post(
        "/commit", json={"document": changed, "reveal": ["/issuer"]}
    ).json()["root"]
    assert r3 != r1


def test_escaped_pointer_tokens_roundtrip():
    path = "/deep/a~1b/tilde~0key/0"
    committed = _commit([path]).json()
    assert committed["leaves"][0]["value"] == 7
    ok = client.post(
        "/verify",
        json={"root": committed["root"], "leaves": committed["leaves"]},
    )
    assert ok.status_code == 200


def test_root_scalar_document():
    committed = client.post(
        "/commit", json={"document": 42, "reveal": [""]}
    ).json()
    assert committed["leaves"][0] == {"path": "", "value": 42, "proof": []}
    ok = client.post(
        "/verify",
        json={"root": committed["root"], "leaves": committed["leaves"]},
    )
    assert ok.status_code == 200


# ---------------------------------------------------------------------------
# Tampering: verifier never touches the original document
# ---------------------------------------------------------------------------


@pytest.fixture()
def disclosure():
    data = _commit(["/subject/age", "/subject/name"]).json()
    return data


def test_tampered_value_rejected(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    leaves[0]["value"] = 37  # forge the age
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert err["loc"] == "leaves[0]"
    assert err["detail"]["path"] == "/subject/age"


def test_tampered_path_rejected(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    leaves[1]["path"] = "/subject/height"
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["loc"] == "leaves[1]"


def test_tampered_sibling_rejected(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    step = leaves[0]["proof"][0]
    step["sibling"] = "00" * 32
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["loc"] == "leaves[0]"


def test_tampered_root_rejected(disclosure):
    forged = "11" * 32
    resp = client.post(
        "/verify", json={"root": forged, "leaves": disclosure["leaves"]}
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert err["detail"]["committedRoot"] == forged


def test_altered_proof_side_rejected(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    leaves[0]["proof"][0]["side"] = (
        "left" if leaves[0]["proof"][0]["side"] == "right" else "right"
    )
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    # Invalid side is a bad-proof structural error; even if the shape stays
    # valid it cannot fold to the committed root.
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Locatable input errors
# ---------------------------------------------------------------------------


def test_missing_field_error_locations():
    resp = client.post("/commit", json={"document": DOC})
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "reveal"

    resp = client.post(
        "/verify", json={"leaves": []}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "root"


def test_pointer_syntax_error():
    resp = _commit(["/subject/a~x"])
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "POINTER_SYNTAX"
    assert err["loc"] == "reveal[0]"


def test_path_not_found_and_container_error():
    resp = _commit(["/subject/nope"])
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "PATH_NOT_FOUND"
    assert err["loc"] == "reveal[0]"

    resp = _commit(["/subject"])
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "PATH_NOT_LEAF"
    assert "/subject/id" in err["detail"]["leafChildren"]

    # Empty container IS a leaf and succeeds.
    assert _commit(["/emptyObj"]).status_code == 200


def test_array_index_out_of_range():
    resp = _commit(["/emails/9"])
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "PATH_NOT_FOUND"


def test_duplicate_reveal_entry():
    resp = _commit(["/issuer", "/issuer"])
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "DUPLICATE_PATH"
    assert err["loc"] == "reveal[1]"


def test_empty_reveal():
    resp = _commit([])
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "EMPTY_REVEAL"


def test_malformed_json_body():
    resp = client.post(
        "/commit", content=b'{"document": {"a": 1},', headers={}
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "INVALID_JSON"
    assert "@char:" in err["loc"]


def test_duplicate_object_key_rejected():
    resp = client.post(
        "/commit",
        content=b'{"document": {"a": 1, "a": 2}, "reveal": ["/a"]}',
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_JSON"


def test_bad_hash_encoding_on_verify(disclosure):
    resp = client.post(
        "/verify",
        json={"root": "not-a-hash", "leaves": disclosure["leaves"]},
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_HASH_ENCODING"
    assert err["loc"] == "root"

    leaves = copy.deepcopy(disclosure["leaves"])
    leaves[0]["proof"][0]["sibling"] = "zz"
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"].endswith(".sibling")


def test_non_leaf_value_on_verify(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    leaves[0]["value"] = {"forged": "object"}
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code in (400, 422)
    # Either rejected as non-leaf value or as root mismatch, but never valid.
    assert resp.status_code != 200


def test_duplicate_verify_path(disclosure):
    leaves = copy.deepcopy(disclosure["leaves"])
    leaves.append(copy.deepcopy(leaves[0]))
    resp = client.post(
        "/verify", json={"root": disclosure["root"], "leaves": leaves}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "DUPLICATE_PATH"


def test_verifier_never_receives_document(disclosure):
    # The verify payload contains only root + selected values + proofs;
    # there is deliberately no place to put the original document.
    resp = client.post(
        "/verify",
        json={
            "root": disclosure["root"],
            "leaves": [disclosure["leaves"][0]],
        },
    )
    assert resp.status_code == 200
    assert "document" not in resp.json()


# ---------------------------------------------------------------------------
# Compact multi-leaf proofs (proofMode="compact")
# ---------------------------------------------------------------------------


DOC_EIGHT = {"k%d" % i: i for i in range(8)}
DOC_FIVE = {"k%d" % i: i for i in range(5)}


def _commit_compact(doc, reveal):
    return client.post(
        "/commit", json={"document": doc, "reveal": reveal, "proofMode": "compact"}
    )


def _compact_verify(data, **overrides):
    body = {
        "root": data["root"],
        "leafCount": data["leafCount"],
        "leaves": copy.deepcopy(data["leaves"]),
        "proof": copy.deepcopy(data["proof"]),
    }
    body.update(overrides)
    return client.post("/verify", json=body)


def test_legacy_default_response_unchanged():
    resp = client.post(
        "/commit", json={"document": DOC_FIVE, "reveal": ["/k0", "/k1"]}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"root", "leaves"}
    assert "proofMode" not in data
    assert "leafCount" not in data
    for leaf in data["leaves"]:
        assert set(leaf.keys()) == {"path", "value", "proof"}
    # Explicit legacy mode is identical in shape.
    explicit = client.post(
        "/commit",
        json={
            "document": DOC_FIVE,
            "reveal": ["/k0", "/k1"],
            "proofMode": "legacy",
        },
    ).json()
    assert explicit == data
    # Legacy verify still works unchanged.
    assert client.post(
        "/verify", json={"root": data["root"], "leaves": data["leaves"]}
    ).status_code == 200


def test_compact_shape_and_indices():
    resp = _commit_compact(DOC, ["/subject/age", "/emails/1", "/emptyObj"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["proofMode"] == "compact"
    assert data["leafCount"] == 11  # leaves of DOC
    # Leaves are sorted by path and carry sorted leaf indices.
    paths = [leaf["path"] for leaf in data["leaves"]]
    assert paths == sorted(paths)
    for leaf in data["leaves"]:
        assert set(leaf.keys()) == {"path", "value", "index"}
        assert 0 <= leaf["index"] < data["leafCount"]
    # Indices are unique and leafCount matches the legacy tree size.
    indices = [leaf["index"] for leaf in data["leaves"]]
    assert len(indices) == len(set(indices))
    # Proof nodes are {level,index,hash}, unique by (level,index), sorted.
    positions = [(node["level"], node["index"]) for node in data["proof"]]
    assert positions == sorted(positions)
    assert len(positions) == len(set(positions))
    for node in data["proof"]:
        assert set(node.keys()) == {"level", "index", "hash"}
        assert len(node["hash"]) == 64


def test_compact_adjacent_leaves_roundtrip_and_dedup():
    legacy = client.post(
        "/commit", json={"document": DOC_EIGHT, "reveal": ["/k0", "/k1"]}
    ).json()
    legacy_siblings = sum(len(leaf["proof"]) for leaf in legacy["leaves"])

    data = _commit_compact(DOC_EIGHT, ["/k0", "/k1"]).json()
    # The two leaves share every level above their own pair: 2*3 legacy
    # siblings collapse to just two uncles.
    assert len(data["proof"]) == 2
    assert legacy_siblings == 6
    resp = _compact_verify(data)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is True
    assert body["root"] == data["root"] == legacy["root"]
    assert [leaf["path"] for leaf in body["leaves"]] == ["/k0", "/k1"]


def test_compact_non_adjacent_leaves_roundtrip():
    data = _commit_compact(DOC_EIGHT, ["/k0", "/k3", "/k7"]).json()
    resp = _compact_verify(data)
    assert resp.status_code == 200, resp.text
    assert [leaf["path"] for leaf in resp.json()["leaves"]] == [
        "/k0",
        "/k3",
        "/k7",
    ]
    # Both leaf-level siblings are present at level 0.
    level0 = {node["index"] for node in data["proof"] if node["level"] == 0}
    assert level0 == {1, 2, 6}


def test_compact_odd_leaf_tree_roundtrips():
    # 5 leaves -> levels [5,3,2,1] with tail duplication at two levels.
    for reveal in [
        ["/k4"],            # lone odd-tail leaf
        ["/k0", "/k1"],     # adjacent pair
        ["/k0", "/k2", "/k4"],  # spread across both odd levels
        ["/k0", "/k1", "/k2", "/k3", "/k4"],  # every leaf disclosed
    ]:
        data = _commit_compact(DOC_FIVE, reveal).json()
        assert data["leafCount"] == 5
        resp = _compact_verify(data)
        assert resp.status_code == 200, (reveal, resp.text)
    # Disclosing every leaf needs no external sibling nodes at all.
    full = _commit_compact(
        DOC_FIVE, ["/k0", "/k1", "/k2", "/k3", "/k4"]
    ).json()
    assert full["proof"] == []


def test_compact_single_leaf_document():
    committed = client.post(
        "/commit",
        json={"document": 42, "reveal": [""], "proofMode": "compact"},
    ).json()
    assert committed["leafCount"] == 1
    assert committed["leaves"] == [{"path": "", "value": 42, "index": 0}]
    assert committed["proof"] == []
    resp = _compact_verify(committed)
    assert resp.status_code == 200, resp.text


def test_compact_odd_tail_node_is_never_carried():
    # Leaf 4 in a 5-leaf tree self-pairs at levels 0 and 1; the generated
    # proof must not contain the duplicated-tail positions (0,4) or (1,2).
    data = _commit_compact(DOC_FIVE, ["/k4"]).json()
    assert (0, 4) not in [(n["level"], n["index"]) for n in data["proof"]]
    assert (1, 2) not in [(n["level"], n["index"]) for n in data["proof"]]
    assert [(n["level"], n["index"]) for n in data["proof"]] == [(2, 0)]
    assert _compact_verify(data).status_code == 200


def test_compact_accepts_unsorted_inputs():
    data = _commit_compact(DOC_FIVE, ["/k0", "/k2", "/k4"]).json()
    reversed_leaves = list(reversed(data["leaves"]))
    reversed_proof = list(reversed(data["proof"]))
    resp = _compact_verify(data, leaves=reversed_leaves, proof=reversed_proof)
    assert resp.status_code == 200, resp.text
    assert [leaf["path"] for leaf in resp.json()["leaves"]] == [
        "/k0",
        "/k2",
        "/k4",
    ]


# --- tampering: structural errors carry precise loc, content is mismatch --


@pytest.fixture()
def compact_data():
    return _commit_compact(DOC_FIVE, ["/k0", "/k4"]).json()


def test_compact_tampered_value_is_root_mismatch(compact_data):
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves[0]["value"] = 11
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert err["loc"] == "root"
    assert "/k0" in err["detail"]["paths"]


def test_compact_tampered_proof_hash_is_root_mismatch(compact_data):
    proof = copy.deepcopy(compact_data["proof"])
    proof[0]["hash"] = "00" * 32
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "ROOT_MISMATCH"


def test_compact_tampered_root_is_root_mismatch(compact_data):
    resp = _compact_verify(compact_data, root="11" * 32)
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert err["detail"]["committedRoot"] == "11" * 32


def test_compact_tampered_index_is_structural(compact_data):
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves[1]["index"] = 5  # == leafCount
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves[1].index"


def test_compact_index_out_of_range_negative(compact_data):
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves[0]["index"] = -1
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leaves[0].index"


def test_compact_duplicate_leaf_index():
    data = _commit_compact(DOC_FIVE, ["/k0", "/k4"]).json()
    leaves = copy.deepcopy(data["leaves"])
    leaves[1]["index"] = leaves[0]["index"]
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves[1].index"


def test_compact_duplicate_proof_position(compact_data):
    proof = copy.deepcopy(compact_data["proof"])
    proof.append(copy.deepcopy(proof[0]))
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == f"proof[{len(compact_data['proof'])}]"


def test_compact_missing_proof_node(compact_data):
    resp = _compact_verify(compact_data, proof=compact_data["proof"][1:])
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert "missing proof node" in err["message"]
    assert err["loc"].startswith("proof[?level=")
    assert err["detail"]["missing"]


def test_compact_surplus_proof_node(compact_data):
    # A node that is not part of the required set for leaves {0, 4} and does
    # not collide with an existing position (level 0 index 1 IS required, so
    # use level 1 index 0, which only belongs to leaf 2's path).
    proof = copy.deepcopy(compact_data["proof"])
    proof.append({"level": 1, "index": 0, "hash": "22" * 32})
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert "surplus proof node" in err["message"]
    assert err["detail"]["surplus"]


def test_compact_odd_tail_proof_node_rejected(compact_data):
    # Position (0,4) is the duplicated odd-layer tail of the 5-leaf level.
    proof = copy.deepcopy(compact_data["proof"])
    proof.append({"level": 0, "index": 4, "hash": "33" * 32})
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_PROOF"


def test_compact_proof_level_out_of_range(compact_data):
    proof = copy.deepcopy(compact_data["proof"])
    proof[0]["level"] = 99
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "proof[0].level"


def test_compact_proof_index_out_of_range(compact_data):
    proof = copy.deepcopy(compact_data["proof"])
    proof[0]["index"] = 99
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "proof[0].index"


def test_compact_bad_hash_encoding(compact_data):
    proof = copy.deepcopy(compact_data["proof"])
    proof[0]["hash"] = "not-hex"
    resp = _compact_verify(compact_data, proof=proof)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_HASH_ENCODING"
    assert err["loc"] == "proof[0].hash"


def test_compact_structural_field_errors(compact_data):
    # leafCount missing -> treated as legacy format and the per-leaf index
    # is then rejected.
    body = {
        "root": compact_data["root"],
        "leaves": copy.deepcopy(compact_data["leaves"]),
        "proof": copy.deepcopy(compact_data["proof"]),
    }
    resp = client.post("/verify", json=body)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_PROOF"

    # leafCount present but wrong type.
    resp = _compact_verify(compact_data, leafCount="5")
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leafCount"

    # More disclosed leaves than leafCount is rejected up front.
    resp = _compact_verify(compact_data, leafCount=1)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves"

    # Adding an extra disclosure changes the required proof set; the stale
    # proof is rejected structurally (here the old leaf-level sibling is
    # now surplus), never silently accepted or reported as content mismatch.
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves.append({"path": "/k1", "value": 1, "index": 1})
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert "surplus proof node" in err["message"]

    # Removing a required node produces the missing-node form instead.
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves.append({"path": "/k2", "value": 2, "index": 2})
    proof = copy.deepcopy(compact_data["proof"])
    proof = [n for n in proof if (n["level"], n["index"]) != (0, 1)]
    resp = _compact_verify(compact_data, leaves=leaves, proof=proof)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert "missing proof node" in err["message"]

    # Empty leaves array.
    resp = _compact_verify(compact_data, leaves=[])
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "EMPTY_REVEAL"

    # Missing per-leaf index.
    leaves = copy.deepcopy(compact_data["leaves"])
    del leaves[0]["index"]
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leaves[0].index"

    # Per-leaf 'proof' is forbidden in compact mode.
    leaves = copy.deepcopy(compact_data["leaves"])
    leaves[0]["proof"] = []
    resp = _compact_verify(compact_data, leaves=leaves)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leaves[0].proof"

    # Top-level proof missing / not an array.
    resp = client.post(
        "/verify",
        json={
            "root": compact_data["root"],
            "leafCount": compact_data["leafCount"],
            "leaves": compact_data["leaves"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "proof"


def test_legacy_leaf_with_index_rejected():
    committed = client.post(
        "/commit", json={"document": DOC_FIVE, "reveal": ["/k0"]}
    ).json()
    leaf = copy.deepcopy(committed["leaves"][0])
    leaf["index"] = 0
    resp = client.post(
        "/verify", json={"root": committed["root"], "leaves": [leaf]}
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves[0].index"


def test_bad_proof_mode_value():
    resp = client.post(
        "/commit",
        json={"document": DOC_FIVE, "reveal": ["/k0"], "proofMode": "verbose"},
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "INVALID_REQUEST"
    assert err["loc"] == "proofMode"


def test_compact_root_independent_of_reveal_and_mode():
    a = _commit_compact(DOC_FIVE, ["/k0"]).json()["root"]
    b = _commit_compact(DOC_FIVE, ["/k2", "/k4"]).json()["root"]
    c = client.post(
        "/commit", json={"document": DOC_FIVE, "reveal": ["/k1"]}
    ).json()["root"]
    assert a == b == c
