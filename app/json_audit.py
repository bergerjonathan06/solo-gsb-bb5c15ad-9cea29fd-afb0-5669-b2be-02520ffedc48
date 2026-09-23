"""Strict JSON document scanning with source mappings for per-string audits.

The scanner implements the RFC 8259 grammar strictly (no ``NaN`` /
``Infinity``, no comments, no single quotes, no unescaped control
characters, no byte order mark) and rejects **duplicate object keys**.
Unpaired UTF-16 surrogates in ``\\uXXXX`` escapes are rejected as well:
the decoded value is persisted verbatim and RFC 8259 leaves the behaviour
of lone surrogates unpredictable.

During the scan every JSON **string value** (object keys are deliberately
skipped) is recorded together with:

* its RFC 6901 JSON Pointer;
* the source offsets of its opening quote and of the character just after
  its closing quote;
* a map from each decoded character's index to the source offset where its
  representation starts (the character itself, or the backslash of an
  escape such as ``\\n`` or ``\\u202E``; a UTF-16 surrogate pair
  ``\\uD83D\\uDE00`` decodes to a single code point mapped to the start of
  the pair).

Each decoded value is then fed to the shared :func:`app.bidi.parse_bidi`
parser, and every control hit / error / dangerous span is mapped back to
line/column in the *original* document rather than in the decoded value.

Nothing is persisted by this module; the caller stores the audits only
after the whole document has scanned and audited cleanly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .bidi import parse_bidi

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
_WHITESPACE = frozenset(" \t\n\r")

# Bidi error messages always name the flagged character as
# "at logical index N ..."; take the first occurrence (the opener of an
# implicit-termination pair, never the terminator mentioned later).
_LOGICAL_INDEX_RE = re.compile(r"at logical index (\d+)")

# Defensive ceiling so a deliberately deep document cannot exhaust the
# Python call stack; well below the interpreter recursion limit.
MAX_JSON_NESTING = 200


# ---------------------------------------------------------------------------
# Errors / model
# ---------------------------------------------------------------------------

class JsonParseError(ValueError):
    """The document is not a valid JSON document or repeats an object key.

    ``pos`` is the 0-based code-point offset in the source where the
    problem becomes visible; ``line`` / ``column`` (1-based) describe the
    same position.
    """

    def __init__(
        self,
        pos: int,
        message: str,
        *,
        code: str = "invalid_json",
        key: str | None = None,
        pointer: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ):
        super().__init__(f"offset {pos}: {message}")
        self.pos = pos
        self.message = message
        self.code = code
        self.key = key
        self.pointer = pointer
        self.line = line
        self.column = column

    @property
    def detail(self) -> dict:
        body: dict = {
            "error": self.code,
            "message": self.message,
            "offset": self.pos,
            "position": {"line": self.line, "column": self.column},
        }
        if self.key is not None:
            body["key"] = self.key
        if self.pointer is not None:
            body["pointer"] = self.pointer
        return body


@dataclass
class _StringValue:
    pointer: str                 # RFC 6901 JSON Pointer ("" for a root string)
    value: str                   # decoded string value
    start: int                   # source offset of the opening quote
    end: int                     # source offset just after closing quote
    source_map: list[int]        # decoded index -> source offset


@dataclass
class JsonValueAudit:
    pointer: str
    start: int
    end: int
    text: str
    result: dict
    locations: dict
    meta: dict


# ---------------------------------------------------------------------------
# JSON Pointer
# ---------------------------------------------------------------------------

def _escape_pointer_token(token: str) -> str:
    """RFC 6901 escaping for a single object-key reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def _render_pointer(segments: list[str]) -> str:
    if not segments:
        return ""
    return "".join("/" + _escape_pointer_token(seg) for seg in segments)


def _line_col(text: str, index: int) -> tuple[int, int]:
    """1-based (line, code-point column) at *index*, matching the bidi API."""
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    return line, index - last_nl


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class _JsonScanner:
    def __init__(self, source: str):
        self.s = source
        self.n = len(source)
        self.values: list[_StringValue] = []

    def _error(
        self,
        pos: int,
        message: str,
        *,
        code: str = "invalid_json",
        key: str | None = None,
        pointer: str | None = None,
    ) -> JsonParseError:
        line, column = _line_col(self.s, min(pos, self.n))
        return JsonParseError(
            pos, message, code=code, key=key, pointer=pointer,
            line=line, column=column,
        )

    def _skip_ws(self, i: int) -> int:
        s = self.s
        while i < self.n and s[i] in _WHITESPACE:
            i += 1
        return i

    # -- strings -----------------------------------------------------------

    def scan_string(self, i: int) -> tuple[str, int, int, list[int]]:
        """Scan a string token beginning with the quote at *i*.

        Returns ``(decoded, start, end, source_map)`` where *end* is the
        offset just after the closing quote and *source_map* maps every
        decoded character index to the start offset of its source
        representation.
        """
        s, n = self.s, self.n
        start = i
        i += 1
        out: list[str] = []
        source_map: list[int] = []

        while True:
            if i >= n:
                raise self._error(start, "unterminated string: missing closing quote")
            ch = s[i]
            cp = ord(ch)
            if ch == '"':
                return "".join(out), start, i + 1, source_map
            if ch == "\\":
                if i + 1 >= n:
                    raise self._error(i, "unterminated escape sequence")
                esc = s[i + 1]
                if esc in _SIMPLE_ESCAPES:
                    source_map.append(i)
                    out.append(_SIMPLE_ESCAPES[esc])
                    i += 2
                    continue
                if esc != "u":
                    raise self._error(
                        i, f"invalid escape sequence: \\{esc}"
                    )
                code = self._read_hex_escape(i)
                i += 6
                if 0xD800 <= code <= 0xDBFF:
                    # High surrogate: it combines only with an immediately
                    # following \uXXXX low surrogate.
                    low = self._try_read_low_surrogate(i)
                    if low is None:
                        # The decoded value must be storable verbatim
                        # (UTF-8), which an unpaired surrogate is not;
                        # RFC 8259 leaves its behaviour unpredictable.
                        raise self._error(
                            i - 6,
                            "unpaired high surrogate in \\u escape: "
                            "expected a low surrogate \\uDC00-\\uDFFF next",
                        )
                    combined = 0x10000 + (
                        ((code - 0xD800) << 10) | (low - 0xDC00)
                    )
                    source_map.append(i - 6)
                    out.append(chr(combined))
                    i += 6
                    continue
                if 0xDC00 <= code <= 0xDFFF:
                    raise self._error(
                        i - 6,
                        "unpaired low surrogate in \\u escape without a "
                        "preceding high surrogate",
                    )
                # BMP code point: one decoded character.
                source_map.append(i - 6)
                out.append(chr(code))
                continue
            if cp < 0x20:
                raise self._error(
                    i,
                    "unescaped control character inside string "
                    f"(U+{cp:04X}); use a \\uXXXX escape",
                )
            # Any other Unicode scalar (including astral characters and
            # U+2028/U+2029, which JSON permits unescaped) passes through.
            source_map.append(i)
            out.append(ch)
            i += 1

    def _read_hex_escape(self, i: int) -> int:
        """Read the four hex digits of ``\\uXXXX`` starting at backslash *i*."""
        s, n = self.s, self.n
        if i + 6 > n or s[i + 1] != "u":
            raise self._error(i, "invalid \\u escape: expected four hex digits")
        digits = s[i + 2:i + 6]
        if len(digits) != 4 or any(c not in _HEX_DIGITS for c in digits):
            raise self._error(i, "invalid \\u escape: expected four hex digits")
        return int(digits, 16)

    def _try_read_low_surrogate(self, i: int) -> int | None:
        """If *i* starts a ``\\uXXXX`` low surrogate, return its value."""
        s, n = self.s, self.n
        if i + 6 > n or s[i] != "\\" or s[i + 1] != "u":
            return None
        digits = s[i + 2:i + 6]
        if any(c not in _HEX_DIGITS for c in digits):
            return None
        code = int(digits, 16)
        return code if 0xDC00 <= code <= 0xDFFF else None

    # -- values ------------------------------------------------------------

    def parse_value(
        self, i: int, segments: list[str], depth: int
    ) -> int:
        if i >= self.n:
            raise self._error(i, "expected a JSON value but reached end of document")
        ch = self.s[i]
        if ch == '"':
            value, start, end, source_map = self.scan_string(i)
            self.values.append(_StringValue(
                pointer=_render_pointer(segments),
                value=value, start=start, end=end, source_map=source_map,
            ))
            return end
        if ch == "{":
            return self.parse_object(i, segments, depth)
        if ch == "[":
            return self.parse_array(i, segments, depth)
        if ch == "-" or "0" <= ch <= "9":
            return self.scan_number(i)
        for literal in ("true", "false", "null"):
            if self.s.startswith(literal, i):
                return i + len(literal)
        raise self._error(i, f"unexpected character {ch!r} where a JSON value is expected")

    def parse_object(
        self, i: int, segments: list[str], depth: int
    ) -> int:
        if depth + 1 > MAX_JSON_NESTING:
            raise self._error(i, f"JSON nesting depth exceeds {MAX_JSON_NESTING}")
        i += 1  # '{'
        i = self._skip_ws(i)
        if i < self.n and self.s[i] == "}":
            return i + 1
        seen: dict[str, int] = {}
        while True:
            i = self._skip_ws(i)
            if i >= self.n:
                raise self._error(i, "unterminated object: expected a string key")
            if self.s[i] != '"':
                raise self._error(
                    i, "object keys must be double-quoted JSON strings"
                )
            key_start = i
            key, _ks, key_end, _map = self.scan_string(i)
            if key in seen:
                raise self._error(
                    key_start,
                    f"duplicate object key {key!r} (first occurrence at "
                    f"offset {seen[key]})",
                    code="duplicate_json_key",
                    key=key,
                    pointer=_render_pointer(segments + [key]),
                )
            seen[key] = key_start

            j = self._skip_ws(key_end)
            if j >= self.n or self.s[j] != ":":
                raise self._error(j, "expected ':' after object key")
            j = self._skip_ws(j + 1)
            j = self.parse_value(j, segments + [key], depth + 1)

            j = self._skip_ws(j)
            if j >= self.n:
                raise self._error(j, "unterminated object: expected ',' or '}'")
            if self.s[j] == ",":
                i = j + 1
                continue
            if self.s[j] == "}":
                return j + 1
            raise self._error(
                j, "expected ',' or '}' after object member"
            )

    def parse_array(
        self, i: int, segments: list[str], depth: int
    ) -> int:
        if depth + 1 > MAX_JSON_NESTING:
            raise self._error(i, f"JSON nesting depth exceeds {MAX_JSON_NESTING}")
        i += 1  # '['
        i = self._skip_ws(i)
        if i < self.n and self.s[i] == "]":
            return i + 1
        index = 0
        while True:
            i = self._skip_ws(i)
            i = self.parse_value(i, segments + [str(index)], depth + 1)
            index += 1

            i = self._skip_ws(i)
            if i >= self.n:
                raise self._error(i, "unterminated array: expected ',' or ']'")
            if self.s[i] == ",":
                i += 1
                continue
            if self.s[i] == "]":
                return i + 1
            raise self._error(
                i, "expected ',' or ']' after array element"
            )

    def scan_number(self, i: int) -> int:
        s, n = self.s, self.n
        if s[i] == "-":
            i += 1
        if i >= n or not ("0" <= s[i] <= "9"):
            raise self._error(i, "invalid number: expected a digit")
        if s[i] == "0":
            i += 1
        else:
            while i < n and "0" <= s[i] <= "9":
                i += 1
        if i < n and s[i] == ".":
            i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise self._error(i, "invalid number: a digit must follow '.'")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        if i < n and s[i] in "eE":
            i += 1
            if i < n and s[i] in "+-":
                i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise self._error(i, "invalid number: a digit must follow the exponent")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        return i

    # -- entry point -------------------------------------------------------

    def parse(self) -> list[_StringValue]:
        if self.n == 0:
            raise JsonParseError(
                0, "empty document: expected a JSON value",
                line=1, column=1,
            )
        i = self._skip_ws(0)
        if i >= self.n:
            raise self._error(0, "whitespace-only document: expected a JSON value")
        end = self.parse_value(i, [], 0)
        tail = self._skip_ws(end)
        if tail < self.n:
            raise self._error(
                tail,
                f"trailing characters after JSON document (found {self.s[tail]!r})",
            )
        return self.values


# ---------------------------------------------------------------------------
# Audit + source mapping
# ---------------------------------------------------------------------------

def _position(line: int, column: int) -> dict:
    return {"line": line, "column": column}


def _build_locations(source: str, sv: _StringValue, result: dict) -> dict:
    """Map a per-value bidi parse result back into the original document."""

    def at_offset(offset: int) -> dict:
        line, column = _line_col(source, offset)
        return _position(line, column)

    def decoded_offset(logical_index: int) -> int:
        if logical_index < len(sv.source_map):
            return sv.source_map[logical_index]
        # One-past-the-last boundary points at the closing quote.
        return sv.end - 1

    controls: list[dict] = []
    for i, control in enumerate(result["controls"]):
        k = control["logical_index"]
        offset = sv.source_map[k]
        controls.append({
            "result_index": i,
            "logical_index": k,
            "pointer": sv.pointer,
            # The representation starts at the character itself, or at the
            # backslash when it came from an escape such as ‮.
            "source_offset": offset,
            "escaped": source[offset] == "\\",
            "position": at_offset(offset),
        })

    errors: list[dict] = []
    for i, message in enumerate(result["errors"]):
        match = _LOGICAL_INDEX_RE.search(message)
        entry: dict = {
            "result_index": i,
            "pointer": sv.pointer,
            "message": message,
            "logical_index": None,
            "source_offset": None,
            "position": None,
        }
        if match is not None:
            k = int(match.group(1))
            offset = decoded_offset(k)
            entry.update({
                "logical_index": k,
                "source_offset": offset,
                "position": at_offset(offset),
            })
        errors.append(entry)

    spans: list[dict] = []
    for i, span in enumerate(result["dangerous_spans"]):
        start_offset = decoded_offset(span["start"])
        # Exclusive end: the slice stops just before the closing quote,
        # which also fully contains a trailing multi-character escape.
        end_offset = sv.end - 1
        if span["end"] < len(sv.value):
            end_offset = sv.source_map[span["end"]]
        spans.append({
            "result_index": i,
            "pointer": sv.pointer,
            "start_logical_index": span["start"],
            "end_logical_index": span["end"],
            "source_offsets": {"start": start_offset, "end": end_offset},
            "position": {
                "start": at_offset(start_offset),
                "end": at_offset(end_offset),
            },
        })

    return {"controls": controls, "errors": errors, "dangerous_spans": spans}


def audit_json_document(raw: bytes | str) -> list[JsonValueAudit]:
    """Strictly scan a JSON document and audit every string value.

    Raises :class:`JsonParseError` (HTTP 422 at the API layer) on invalid
    JSON, duplicate keys or non-UTF-8 input; nothing is persisted here.
    """
    if isinstance(raw, bytes):
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            prefix = raw[: exc.start].decode("utf-8", errors="ignore")
            pos = len(prefix)
            line, column = _line_col(prefix, pos)
            raise JsonParseError(
                pos,
                "document is not valid UTF-8: undecodable byte sequence",
                line=line, column=column,
            )
    else:
        source = raw

    # RFC 8259 forbids adding a BOM; reject it instead of silently ignoring.
    if source.startswith("\ufeff"):
        raise JsonParseError(
            0, "unexpected byte order mark (BOM); JSON text must begin directly",
            line=1, column=1,
        )

    string_values = _JsonScanner(source).parse()

    audits: list[JsonValueAudit] = []
    for sv in string_values:
        result = parse_bidi(sv.value).to_dict()
        locations = _build_locations(source, sv, result)
        meta = {
            "source": "json",
            "version": 1,
            "json_pointer": sv.pointer,
            "string_start": sv.start,
            "string_end": sv.end,
            "locations": locations,
        }
        audits.append(JsonValueAudit(
            pointer=sv.pointer,
            start=sv.start,
            end=sv.end,
            text=sv.value,
            result=result,
            locations=locations,
            meta=meta,
        ))
    return audits
