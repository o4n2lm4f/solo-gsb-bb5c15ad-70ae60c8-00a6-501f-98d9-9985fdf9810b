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
# Compact multi-leaf proofs
# ---------------------------------------------------------------------------


FIVE = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}
# Leaves sort to /a,/b,/c,/d,/e -> indices 0..4; sizes [5,3,2,1].


def _compact_commit(doc, reveal):
    return client.post(
        "/commit",
        json={"document": doc, "reveal": reveal, "proofMode": "compact"},
    )


def _compact_verify(data, **overrides):
    payload = {
        "root": data["root"],
        "leafCount": data["leafCount"],
        "leaves": copy.deepcopy(data["leaves"]),
        "proofNodes": copy.deepcopy(data["proofNodes"]),
    }
    payload.update(overrides)
    return client.post("/verify", json=payload)


def test_compact_commit_response_shape():
    resp = _compact_commit(FIVE, ["/a", "/c", "/e"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["proofMode"] == "compact"
    assert data["leafCount"] == 5
    assert [(leaf["path"], leaf["index"]) for leaf in data["leaves"]] == [
        ("/a", 0),
        ("/c", 2),
        ("/e", 4),
    ]
    for leaf in data["leaves"]:
        assert set(leaf.keys()) == {"path", "index", "value"}
    nodes = [(n["level"], n["index"]) for n in data["proofNodes"]]
    # Folding {0,2,4} bottom up needs leaves 1 and 3 as level-0 siblings and
    # the level-1 subtree at index 2 (H(d,e)); each exactly once.
    assert nodes == sorted(nodes)
    assert len(nodes) == len(set(nodes))


def test_compact_roundtrip_adjacent_leaves():
    data = _compact_commit(DOC, ["/subject/age", "/subject/id"]).json()
    resp = _compact_verify(data)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is True
    assert body["proofMode"] == "compact"
    assert [leaf["path"] for leaf in body["leaves"]] == [
        "/subject/age",
        "/subject/id",
    ]


def test_compact_roundtrip_non_adjacent_leaves():
    data = _compact_commit(DOC, ["/issuer", "/subject/age", "/emptyObj"]).json()
    resp = _compact_verify(data)
    assert resp.status_code == 200, resp.text
    # Leaves may be submitted in any order; the response is path-sorted.
    shuffled = {"root": data["root"], "leafCount": data["leafCount"],
                "leaves": list(reversed(data["leaves"])),
                "proofNodes": data["proofNodes"]}
    resp2 = client.post("/verify", json=shuffled)
    assert resp2.status_code == 200
    assert [leaf["path"] for leaf in resp2.json()["leaves"]] == sorted(
        leaf["path"] for leaf in data["leaves"]
    )


def test_compact_odd_leaf_tree_and_odd_levels():
    data = _compact_commit(FIVE, ["/e"]).json()
    # n=5 sizes [5,3,2,1]: the tail leaf 4 self-pairs at level 0, so no
    # level-0 node with index 4 may be present.
    assert all(
        not (node["level"] == 0 and node["index"] == 4)
        for node in data["proofNodes"]
    )
    assert _compact_verify(data).status_code == 200

    # Disclosing the tail and a far leaf exercises an odd level 1 too.
    data = _compact_commit(FIVE, ["/a", "/e"]).json()
    assert _compact_verify(data).status_code == 200

    # Three leaves and a single disclosed tail: first fold is H(L2,L2).
    three = {"a": 1, "b": 2, "c": 3}
    data = _compact_commit(three, ["/c"]).json()
    assert [(n["level"], n["index"]) for n in data["proofNodes"]] == [(1, 0)]
    assert _compact_verify(data).status_code == 200


def test_compact_proof_nodes_deduplicated():
    # Adjacent disclosed leaves share upper-path nodes; the compact proof
    # must be strictly smaller than the concatenated legacy proofs.
    legacy = _commit(["/subject/age", "/subject/id"]).json()
    compact = _compact_commit(DOC, ["/subject/age", "/subject/id"]).json()
    legacy_count = sum(len(leaf["proof"]) for leaf in legacy["leaves"])
    assert len(compact["proofNodes"]) < legacy_count
    keys = [(n["level"], n["index"]) for n in compact["proofNodes"]]
    assert len(keys) == len(set(keys))


def test_compact_all_and_single_leaf_trees():
    data = _compact_commit(FIVE, ["/a", "/b", "/c", "/d", "/e"]).json()
    assert data["proofNodes"] == []
    assert _compact_verify(data).status_code == 200

    single = client.post(
        "/commit",
        json={"document": 42, "reveal": [""], "proofMode": "compact"},
    ).json()
    assert single["leafCount"] == 1
    assert single["proofNodes"] == []
    assert single["leaves"] == [{"path": "", "index": 0, "value": 42}]
    assert _compact_verify(single).status_code == 200


def test_default_mode_response_unchanged_and_proofmode_validation():
    resp = client.post(
        "/commit", json={"document": FIVE, "reveal": ["/a"]}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"root", "leaves"}
    assert set(body["leaves"][0].keys()) == {"path", "value", "proof"}
    assert "proofMode" not in body and "leafCount" not in body

    # Explicit standard is identical in shape.
    resp2 = client.post(
        "/commit",
        json={"document": FIVE, "reveal": ["/a"], "proofMode": "standard"},
    )
    assert set(resp2.json().keys()) == {"root", "leaves"}

    resp3 = client.post(
        "/commit",
        json={"document": FIVE, "reveal": ["/a"], "proofMode": "verbose"},
    )
    assert resp3.status_code == 400
    err = resp3.json()["error"]
    assert err["code"] == "INVALID_REQUEST"
    assert err["loc"] == "proofMode"

    # Legacy verifications produced by the legacy commit still verify.
    assert client.post(
        "/verify",
        json={"root": body["root"], "leaves": body["leaves"]},
    ).status_code == 200


def test_compact_auto_detection_mixes_without_mode_field():
    data = _compact_commit(FIVE, ["/b", "/d"]).json()
    # No proofMode in the verify request; presence of proofNodes triggers it.
    payload = {
        "root": data["root"],
        "leafCount": data["leafCount"],
        "leaves": data["leaves"],
        "proofNodes": data["proofNodes"],
    }
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 200
    assert resp.json()["proofMode"] == "compact"


def test_compact_tampered_values_and_hashes_return_root_mismatch():
    data = _compact_commit(FIVE, ["/a", "/c", "/e"]).json()

    leaves = copy.deepcopy(data["leaves"])
    leaves[0]["value"] = 999
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert err["loc"] == "root"
    assert err["detail"]["rebuiltRoot"] != data["root"]

    leaves = copy.deepcopy(data["leaves"])
    leaves[1]["path"] = "/z"
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "ROOT_MISMATCH"

    nodes = copy.deepcopy(data["proofNodes"])
    nodes[0]["hash"] = "ab" * 32
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "ROOT_MISMATCH"
    assert "tampered" in err["detail"]["hint"]

    resp = _compact_verify(data, root="11" * 32)
    assert resp.status_code == 422
    assert resp.json()["error"]["detail"]["committedRoot"] == "11" * 32


def test_compact_leaf_index_out_of_range():
    data = _compact_commit(FIVE, ["/a"]).json()
    leaves = copy.deepcopy(data["leaves"])
    leaves[0]["index"] = 5
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves[0].index"
    assert err["detail"]["leafCount"] == 5


def test_compact_duplicate_leaf_index():
    data = _compact_commit(FIVE, ["/a", "/b"]).json()
    leaves = copy.deepcopy(data["leaves"])
    leaves[1]["index"] = leaves[0]["index"]
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "leaves[1].index"


def test_compact_missing_proof_node():
    data = _compact_commit(FIVE, ["/a"]).json()
    nodes = copy.deepcopy(data["proofNodes"])
    removed = nodes.pop()
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == "proofNodes"
    assert {"level": removed["level"], "index": removed["index"]} in (
        err["detail"]["missing"]
    )


def test_compact_extraneous_proof_node():
    data = _compact_commit(FIVE, ["/a"]).json()
    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append({"level": 0, "index": 1, "hash": "00" * 32})
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == f"proofNodes[{len(data['proofNodes'])}]"


def test_compact_duplicate_proof_node():
    data = _compact_commit(FIVE, ["/a"]).json()
    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append(copy.deepcopy(nodes[0]))
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == f"proofNodes[{len(data['proofNodes'])}]"


def test_compact_odd_level_tail_node_rejected():
    data = _compact_commit(FIVE, ["/a"]).json()
    # Level 0 has 5 nodes: index 4 is the odd tail and must not be supplied.
    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append({"level": 0, "index": 4, "hash": "00" * 32})
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"
    assert err["loc"] == f"proofNodes[{len(data['proofNodes'])}]"
    assert "odd-sized level" in err["message"]

    # Proof nodes may not shadow a disclosed leaf either.
    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append({"level": 0, "index": 0, "hash": "00" * 32})
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "BAD_PROOF"


def test_compact_node_level_and_index_range():
    data = _compact_commit(FIVE, ["/a"]).json()

    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append({"level": 3, "index": 0, "hash": "00" * 32})  # root level
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["loc"] == f"proofNodes[{len(data['proofNodes'])}].level"

    nodes = copy.deepcopy(data["proofNodes"])
    nodes.append({"level": 1, "index": 99, "hash": "00" * 32})
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["loc"] == f"proofNodes[{len(data['proofNodes'])}].index"


def test_compact_field_type_and_encoding_errors():
    data = _compact_commit(FIVE, ["/a"]).json()

    # leafCount missing / wrong type
    payload = _compact_verify(data)  # ensure baseline first
    assert payload.status_code == 200
    resp = client.post(
        "/verify",
        json={
            "root": data["root"],
            "leaves": data["leaves"],
            "proofNodes": data["proofNodes"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leafCount"

    nodes = copy.deepcopy(data["proofNodes"])
    nodes[0]["hash"] = "zz"
    resp = _compact_verify(data, proofNodes=nodes)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_HASH_ENCODING"
    assert err["loc"] == "proofNodes[0].hash"

    resp = _compact_verify(data, proofNodes="nope")
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "proofNodes"

    leaves = copy.deepcopy(data["leaves"])
    leaves[0]["index"] = -1
    resp = _compact_verify(data, leaves=leaves)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leaves[0].index"


def test_compact_wrong_leaf_count_is_structural_error():
    data = _compact_commit(FIVE, ["/a"]).json()

    # leafCount below a disclosed index is a structural range error.
    resp = _compact_verify(data, leafCount=1)
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "BAD_PROOF"

    # Zero and non-integer leaf counts are structural input errors.
    resp = _compact_verify(data, leafCount=0)
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leafCount"

    resp = client.post(
        "/verify",
        json={
            "root": data["root"],
            "leafCount": "five",
            "leaves": data["leaves"],
            "proofNodes": data["proofNodes"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["loc"] == "leafCount"


def test_compact_and_standard_share_the_same_root_and_leaf_hashes():
    from app.tree import expand_leaves

    reveal = ["/issuer", "/subject/name", "/emails/0", "/emptyArr"]
    std = _commit(reveal).json()
    compact = _compact_commit(DOC, reveal).json()
    assert std["root"] == compact["root"]
    assert compact["leafCount"] == len(expand_leaves(DOC))
    # The same values are disclosed under identical (sorted) paths.
    assert [l["path"] for l in std["leaves"]] == [
        l["path"] for l in compact["leaves"]
    ]
    assert [l["value"] for l in std["leaves"]] == [
        l["value"] for l in compact["leaves"]
    ]
    # Compact indices are unique and match the sorted-pointer ordering.
    paths = [l["path"] for l in compact["leaves"]]
    assert paths == sorted(paths)
    indices = [l["index"] for l in compact["leaves"]]
    assert len(set(indices)) == len(indices)


@pytest.mark.parametrize("seed", range(10))
def test_compact_randomized_roundtrips(seed):
    import random

    rng = random.Random(seed)
    width = rng.randint(1, 13)
    doc = {f"k{i:02d}": i for i in range(width)}
    count = rng.randint(1, width)
    reveal = [f"/k{i:02d}" for i in rng.sample(range(width), count)]
    committed = _compact_commit(doc, reveal)
    assert committed.status_code == 200, committed.text
    data = committed.json()

    # Structural invariants: unique/sorted nodes, no odd-tail or root nodes.
    keys = [(n["level"], n["index"]) for n in data["proofNodes"]]
    assert keys == sorted(set(keys))

    # Verify with the leaves shuffled and proof nodes shuffled too.
    leaves = data["leaves"][:]
    nodes = data["proofNodes"][:]
    rng.shuffle(leaves)
    rng.shuffle(nodes)
    resp = client.post(
        "/verify",
        json={
            "root": data["root"],
            "leafCount": data["leafCount"],
            "leaves": leaves,
            "proofNodes": nodes,
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["valid"] is True
