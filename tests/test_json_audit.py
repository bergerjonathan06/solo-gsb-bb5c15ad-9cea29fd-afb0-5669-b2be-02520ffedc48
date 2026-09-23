"""Tests for the raw JSON document audit endpoint (POST /api/v1/audits/json).

Covers: recursive string-value discovery (objects/arrays, keys skipped),
RFC 6901 pointers, source offsets of each string token, ‑style escape
decoding with source mapping (incl. UTF-16 surrogate pairs), no false
positives on ordinary escapes or keys, strict-RFC 8259 rejection (422),
duplicate-key rejection (422), all-or-nothing persistence, and interplay
with the stored record (GET/verify).
"""

RLO = "‮"
PDF = "‬"
RLI = "⁧"
PDI = "⁩"


def _post(client, doc):
    if isinstance(doc, str):
        doc = doc.encode("utf-8")
    return client.post(
        "/api/v1/audits/json",
        content=doc,
        headers={"Content-Type": "application/json"},
    )


def _total(client):
    return client.get("/api/v1/audits").json()["total"]


# ------------------------------------------------------------ happy path ---

def test_basic_value_audit_and_key_skipped(client):
    # The key carries a raw RLO: keys are never audited.
    doc = '{"%sk": "ab%scd%s"}' % (RLO, RLO, PDF)
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["value_count"] == 1
    assert body["risk_level"] == "high"

    item = body["items"][0]
    assert item["json_pointer"] == "/%sk" % RLO
    assert item["risk_level"] == "high"
    assert item["control_count"] == 2
    assert item["dangerous_span_count"] == 1
    # string_offsets bracket the whole "..." token of the value
    start, end = (item["string_offsets"][k] for k in ("start", "end"))
    assert doc[start] == '"' and doc[end - 1] == '"'
    assert doc[start:end] == '"ab%scd%s"' % (RLO, PDF)

    controls = item["locations"]["controls"]
    assert [c["logical_index"] for c in controls] == [2, 5]
    # raw (unescaped) control characters map to themselves
    assert controls[0]["source_offset"] == doc.index(RLO, start)
    assert controls[0]["escaped"] is False
    assert controls[0]["position"] == {"line": 1, "column": controls[0]["source_offset"] + 1}

    span = item["locations"]["dangerous_spans"][0]
    assert span["start_logical_index"] == 2
    assert span["end_logical_index"] == 5
    # source slice covers exactly the override scope in the document
    so = span["source_offsets"]
    assert doc[so["start"]:so["end"]] == "%scd" % (RLO,)


def test_nested_pointers_and_rfc6901_escaping(client):
    doc = (
        '{"a/b": {"~tilde": ["x", ["%s"]]}, "plain": 1}'
        % RLO
    )
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    items = resp.json()["items"]
    pointers = [i["json_pointer"] for i in items]
    assert pointers == ["/a~1b/~0tilde/0", "/a~1b/~0tilde/1/0"]
    assert items[1]["risk_level"] == "critical"  # unclosed RLO
    assert resp.json()["risk_level"] == "critical"


def test_unicode_escape_maps_to_backslash(client):
    doc = '{"a": "x\\u202Ey\\u202C"}'
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    assert item["result"]["length"] == 4  # decoded: x, RLO, y, PDF
    controls = item["locations"]["controls"]
    assert [c["logical_index"] for c in controls] == [1, 3]
    assert all(c["escaped"] for c in controls)
    # each escape maps to the offset of its backslash
    assert doc[controls[0]["source_offset"]:].startswith("\\u202E")
    assert doc[controls[1]["source_offset"]:].startswith("\\u202C")
    assert controls[0]["position"] == {"line": 1, "column": controls[0]["source_offset"] + 1}


def test_surrogate_pair_decodes_to_single_codepoint(client):
    # 😀 is U+1F600 = D83D DE00; the RLO after it is decoded index 1.
    doc = '{"e": "\\uD83D\\uDE00\\u202E"}'
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    assert item["result"]["length"] == 2
    controls = item["locations"]["controls"]
    assert len(controls) == 1
    assert controls[0]["logical_index"] == 1
    assert doc[controls[0]["source_offset"]:].startswith("\\u202E")


def test_astral_literal_and_multiline_positions(client):
    doc = '{\n  "emoji": "😀",\n  "bad": "q%s"\n}' % RLO
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    items = resp.json()["items"]
    assert [i["json_pointer"] for i in items] == ["/emoji", "/bad"]
    ctrl = items[1]["locations"]["controls"][0]
    assert ctrl["position"]["line"] == 3
    # column counts code points (the emoji line does not disturb line 3)
    line3 = doc.split("\n")[2]
    assert ctrl["position"]["column"] == line3.index(RLO) + 1


def test_ordinary_escapes_are_not_hits(client):
    # \n \" \\ \/ and an escaped backslash before u202e: no bidi controls.
    doc = '{"a": "line\\nbreak", "b": "quo\\"te", "c": "\\\\u202e", "d": "a\\/b"}'
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 4
    assert body["risk_level"] == "info"
    assert all(i["control_count"] == 0 for i in body["items"])
    # decoded values are what json.loads would produce
    assert body["items"][0]["result"]["length"] == len("line\nbreak")
    assert body["items"][2]["result"]["length"] == len("\\u202e")


def test_escaped_key_not_audited_even_when_escaped_control(client):
    doc = '{"\\u202E": "clean", "\\u2067nested": {"\\u202E": "also clean"}}'
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 2
    assert body["risk_level"] == "info"
    assert all(i["control_count"] == 0 for i in body["items"])


def test_root_scalar_string_and_empty_containers(client):
    resp = _post(client, '"%s"' % RLO)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 1
    assert body["items"][0]["json_pointer"] == ""
    assert body["risk_level"] == "critical"

    for doc in ("{}", "[]", "123", "true", "null", '"ok"'):
        resp = _post(client, doc)
        assert resp.status_code == 201, (doc, resp.text)
    assert _post(client, "{}").json()["value_count"] == 0
    assert _post(client, "{}").json()["risk_level"] == "info"


def test_numbers_and_literals_strictly_validated(client):
    ok = '[0, -1, 3.14, 1e10, 2.5E-3, -0.5e+2, true, false, null]'
    assert _post(client, ok).status_code == 201
    for bad in ("01", "1.", ".5", "+1", "1e", "1e+", "-", "NaN", "Infinity",
                "tru", "nulll", "0x10"):
        resp = _post(client, bad)
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]["error"] == "invalid_json"


def test_unclosed_rlo_error_maps_to_source(client):
    doc = '{\n  "a": "%send.js"\n}' % RLO
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    assert item["risk_level"] == "critical"
    errors = item["locations"]["errors"]
    assert len(errors) == 1
    assert errors[0]["logical_index"] == 0
    assert errors[0]["source_offset"] == doc.index(RLO)
    assert errors[0]["position"]["line"] == 2
    assert "never closed by PDF" in errors[0]["message"]


def test_isolate_pair_balanced_medium_risk(client):
    doc = '{"a": "%sx%s"}' % (RLI, PDI)
    resp = _post(client, doc)
    assert resp.status_code == 201
    item = resp.json()["items"][0]
    assert item["risk_level"] == "medium"  # RLI is medium even when closed
    assert item["error_count"] == 0


def test_records_persisted_and_verifiable(client):
    doc = '{"a": "%sx%s", "b": "clean"}' % (RLO, PDF)
    resp = _post(client, doc)
    assert resp.status_code == 201
    ids = [i["id"] for i in resp.json()["items"]]
    assert len(set(ids)) == 2
    assert _total(client) == 2

    record = client.get(f"/api/v1/audits/{ids[0]}").json()
    assert record["raw_text"] == "%sx%s" % (RLO, PDF)
    assert record["meta"]["source"] == "json"
    assert record["meta"]["json_pointer"] == "/a"
    assert record["meta"]["locations"]["controls"][0]["source_offset"] == doc.index(RLO)
    # stored result still re-parses identically
    verify = client.get(f"/api/v1/audits/{ids[0]}/verify").json()
    assert verify["consistent"] is True


# ------------------------------------------------------------------ 422s ---

def test_duplicate_key_rejected(client):
    resp = _post(client, '{"a": 1, "a": 2}')
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_json_key"
    assert detail["key"] == "a"
    assert detail["pointer"] == "/a"
    assert detail["position"]["line"] == 1
    assert _total(client) == 0


def test_duplicate_key_nested_and_escape_normalised(client):
    # duplicates are detected per object, after escape decoding
    resp = _post(client, '{"outer": {"a": 1, "\\u0061": 2}}')
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_json_key"
    assert detail["pointer"] == "/outer/a"
    assert _total(client) == 0

    # same key in *different* objects is fine
    resp = _post(client, '{"a": {"k": "x"}, "b": {"k": "y"}}')
    assert resp.status_code == 201
    assert _total(client) == 2


def test_invalid_json_rejected_without_partial_writes(client):
    docs = [
        "",                      # empty body
        "   \n\t ",              # whitespace only
        '{"a": }',               # missing value
        '{"a" 1}',               # missing colon
        '{"a": 1',               # unterminated object
        '[1, 2',                 # unterminated array
        '[1,]',                  # trailing comma
        '{"a": 1,}',             # trailing comma in object
        "{'a': 1}",              # single quotes
        '"unterminated',         # unterminated string
        '"bad \\x escape"',      # invalid escape
        '"bad \\u12 escape"',    # short ù escape
        '"bad \\uZZZZ escape"',  # non-hex escape
        '"tab\there"',           # raw control character in string
        '{"a": 1} trailing',     # garbage after document
        '[1] [2]',               # two documents
        "\ufeff{}",        # byte order mark
    ]
    for doc in docs:
        resp = _post(client, doc)
        assert resp.status_code == 422, repr(doc)
        detail = resp.json()["detail"]
        assert detail["error"] == "invalid_json", repr(doc)
        assert detail["position"]["line"] >= 1
        assert detail["position"]["column"] >= 1
    assert _total(client) == 0


def test_invalid_utf8_body_rejected(client):
    resp = client.post(
        "/api/v1/audits/json",
        content=b'{"a": "\xff\xfe"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_json"
    assert _total(client) == 0


def test_escaped_quote_does_not_hide_garbage(client):
    # the \" is an escaped quote, so the string runs past it and the
    # document is unterminated -> 422, and nothing is stored
    resp = _post(client, '{"a": "\\"}')
    assert resp.status_code == 422
    assert _total(client) == 0


def test_unpaired_surrogates_rejected(client):
    # Unpaired surrogates cannot be stored verbatim (not valid UTF-8) and
    # RFC 8259 leaves their behaviour unpredictable: rejected as invalid.
    for doc in ('{"a": "\\uD800"}', '{"a": "\\uDE00"}',
                '{"a": "\\uD800x"}', '{"a": "\\uD800\\uD800"}',
                '{"a": "\\uD800\\u0041"}'):
        resp = _post(client, doc)
        assert resp.status_code == 422, doc
        assert resp.json()["detail"]["error"] == "invalid_json"
    assert _total(client) == 0


def test_deep_nesting_rejected(client):
    doc = "[" * 300 + "]" * 300
    resp = _post(client, doc)
    assert resp.status_code == 422
    assert "nesting" in resp.json()["detail"]["message"]
    assert _total(client) == 0


def test_mixed_document_risk_aggregation(client):
    doc = (
        '{"clean": "hello", "nums": [1, 2.5, -3e2],'
        ' "nested": {"list": ["%sa%s", "ok", {"deep": "%s"}]}}'
        % (RLO, PDF, RLI)
    )
    resp = _post(client, doc)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 4
    assert body["risk_level"] == "high"
    pointers = [i["json_pointer"] for i in body["items"]]
    assert pointers == ["/clean", "/nested/list/0", "/nested/list/1",
                        "/nested/list/2/deep"]
    risks = {i["json_pointer"]: i["risk_level"] for i in body["items"]}
    assert risks["/nested/list/0"] == "high"
    assert risks["/nested/list/2/deep"] == "medium"
    assert _total(client) == 4
