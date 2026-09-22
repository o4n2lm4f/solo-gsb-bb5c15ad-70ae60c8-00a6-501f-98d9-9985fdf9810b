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
