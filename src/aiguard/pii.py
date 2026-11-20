"""Validators and redactor for Turkish and English personal data.

Detection is a candidate search followed by a checksum or structural check.
An 11-digit order number, a spaced account string, or a digit run that only
looks like a card is left unchanged when that check fails.

Placeholders are stable for the same canonical value inside one
``RedactionSession``. The session holds the reverse map in memory and nowhere
else; callers must not write that map to a log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# ISO 13616 IBAN lengths. Countries absent from this map are ignored.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24,
    "RS": 22, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
    "SM": 27, "ST": 25, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22,
    "VG": 24, "XK": 20,
}

PII_ORDER: tuple[str, ...] = ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL")

# Turkish mobile numbering: 50x, 53x, 54x, 55x, plus assigned 516 and 561.
_EXPLICIT_MOBILE_PREFIXES = {"516", "561"}

_TCKN_RE = re.compile(r"(?<![0-9])([1-9][0-9]{10})(?![0-9])")
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
)
_PHONE_RE = re.compile(
    r"(?<![0-9])\(?"
    r"(?:"
    r"(?:\+|00)[\s().\-]*90[\s().\-]*5[0-9]{2}(?:[\s().\-]*[0-9]){7}"
    r"|"
    r"0[\s().\-]*5[0-9]{2}(?:[\s().\-]*[0-9]){7}"
    r")"
    r"(?![\s().\-]*[0-9])"
)
_IBAN_START_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2}[0-9]{2})")


class PiiType(str, Enum):
    TCKN = "TCKN"
    IBAN = "IBAN"
    CARD = "CARD"
    PHONE = "PHONE"
    EMAIL = "EMAIL"


_PRIORITY = {
    PiiType.IBAN: 5,
    PiiType.CARD: 4,
    PiiType.EMAIL: 3,
    PiiType.PHONE: 2,
    PiiType.TCKN: 1,
}


@dataclass(frozen=True)
class Finding:
    """A redaction in the original string. Offsets are half-open and local to that string."""

    type: str
    placeholder: str
    start: int
    end: int

    def as_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "placeholder": self.placeholder,
            "start": self.start,
            "end": self.end,
        }


@dataclass(frozen=True)
class Redaction:
    text: str
    findings: list[Finding]


@dataclass(frozen=True)
class _Candidate:
    start: int
    end: int
    type: PiiType
    raw: str
    canonical: str
    priority: int


def ordered_counts(counts: dict[str, int]) -> dict[str, int]:
    return {name: counts[name] for name in PII_ORDER if counts.get(name)}


def is_valid_tckn(value: str) -> bool:
    """Turkish national ID checksum.

    Digit 10 is ``((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10``.
    Digit 11 is the sum of the first 10 digits mod 10.
    The first digit is never zero.
    """

    if len(value) != 11 or not value.isdigit() or value[0] == "0":
        return False
    digits = [int(char) for char in value]
    odd = sum(digits[0:9:2])
    even = sum(digits[1:8:2])
    tenth = (odd * 7 - even) % 10
    if digits[9] != tenth:
        return False
    return digits[10] == sum(digits[:10]) % 10


def compact_iban(value: str) -> str:
    return "".join(char for char in value if char not in " -").upper()


def is_valid_iban(value: str) -> bool:
    """Country length plus ISO 7064 mod-97. Spaces and dashes are ignored."""

    if any(not (char.isalnum() or char in " -") or not char.isascii() for char in value):
        return False
    compact = compact_iban(value)
    if len(compact) < 15 or len(compact) > 34:
        return False
    if not compact.isalnum() or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    expected = IBAN_LENGTHS.get(compact[:2])
    if expected is None or len(compact) != expected:
        return False
    return _iban_mod97(compact) == 1


def _iban_mod97(compact: str) -> int:
    rearranged = compact[4:] + compact[:4]
    pieces: list[str] = []
    for char in rearranged:
        if char.isdigit():
            pieces.append(char)
        else:
            pieces.append(str(ord(char) - 55))
    return int("".join(pieces)) % 97


def is_valid_card(value: str) -> bool:
    """Luhn, length 13-19, spaces or dashes allowed, and a known scheme prefix."""

    if any(not (char.isdigit() or char in " -") for char in value):
        return False
    digits = "".join(char for char in value if char.isdigit())
    return _card_digits_valid(digits)


def _card_digits_valid(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    if not _luhn_ok(digits):
        return False
    return _scheme_ok(digits)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _scheme_ok(digits: str) -> bool:
    length = len(digits)
    if digits.startswith("4") and length in (13, 16, 19):
        return True
    if length == 16 and digits[:2] in {"51", "52", "53", "54", "55"}:
        return True
    if length == 16 and digits[:4].isdigit() and 2221 <= int(digits[:4]) <= 2720:
        return True
    if length == 15 and digits[:2] in {"34", "37"}:
        return True
    if length in range(16, 20) and (
        digits.startswith("6011")
        or digits.startswith("65")
        or (digits[:3].isdigit() and 644 <= int(digits[:3]) <= 649)
    ):
        return True
    if length == 16 and digits.startswith("9792"):
        return True
    if length == 14 and (
        digits[:2] in {"36", "38"}
        or (digits[:3].isdigit() and 300 <= int(digits[:3]) <= 305)
    ):
        return True
    if length in range(16, 20) and digits[:4].isdigit() and 3528 <= int(digits[:4]) <= 3589:
        return True
    return False


def is_valid_phone(value: str) -> bool:
    """Turkish mobiles written as +90, 0090, or a leading 0 before 5xx."""

    return _canonical_phone(value) is not None


def _canonical_phone(value: str) -> str | None:
    if any(not (char.isdigit() or char in "+ ().-\t") for char in value):
        return None
    digits = "".join(char for char in value if char.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("90") and len(digits) == 12:
        national = digits[2:]
    elif digits.startswith("0") and len(digits) == 11:
        national = digits[1:]
    else:
        return None
    if len(national) != 10 or not national.startswith("5"):
        return None
    prefix = national[:3]
    if prefix not in _EXPLICIT_MOBILE_PREFIXES and prefix[1] not in "0345":
        return None
    return "90" + national


def is_valid_email(value: str) -> bool:
    if len(value) > 254 or value.count("@") != 1:
        return False
    local, domain = value.split("@")
    if not local or not domain or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local or ".." in domain:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._%+\-]+", local):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not tld.isalpha() or not (2 <= len(tld) <= 24):
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9\-]+", label):
            return False
    return True


def _find_tckn(text: str) -> list[_Candidate]:
    found: list[_Candidate] = []
    for match in _TCKN_RE.finditer(text):
        raw = match.group(1)
        if is_valid_tckn(raw):
            found.append(_Candidate(match.start(1), match.end(1), PiiType.TCKN, raw, raw, _PRIORITY[PiiType.TCKN]))
    return found


def _find_emails(text: str) -> list[_Candidate]:
    found: list[_Candidate] = []
    for match in _EMAIL_RE.finditer(text):
        raw = match.group(0)
        if is_valid_email(raw):
            found.append(
                _Candidate(
                    match.start(),
                    match.end(),
                    PiiType.EMAIL,
                    raw,
                    raw.lower(),
                    _PRIORITY[PiiType.EMAIL],
                )
            )
    return found


def _find_phones(text: str) -> list[_Candidate]:
    found: list[_Candidate] = []
    for match in _PHONE_RE.finditer(text):
        raw = match.group(0)
        canonical = _canonical_phone(raw)
        if canonical is None:
            continue
        found.append(
            _Candidate(match.start(), match.end(), PiiType.PHONE, raw, canonical, _PRIORITY[PiiType.PHONE])
        )
    return found


def _find_ibans(text: str) -> list[_Candidate]:
    found: list[_Candidate] = []
    for match in _IBAN_START_RE.finditer(text):
        country = match.group(1)[:2].upper()
        target = IBAN_LENGTHS.get(country)
        if target is None:
            continue
        chars: list[str] = []
        index = match.start()
        end = index
        while index < len(text) and len(chars) < target:
            char = text[index]
            if char.isascii() and char.isalnum():
                chars.append(char.upper())
                index += 1
                end = index
                continue
            if chars and char in " -":
                probe = index
                while probe < len(text) and text[probe] in " -":
                    probe += 1
                if (
                    probe < len(text)
                    and text[probe].isascii()
                    and text[probe].isalnum()
                    and len(chars) < target
                ):
                    index = probe
                    continue
            break
        if len(chars) != target:
            continue
        if end < len(text) and text[end].isascii() and text[end].isalnum():
            continue
        normalized = "".join(chars)
        if not is_valid_iban(normalized):
            continue
        found.append(
            _Candidate(match.start(), end, PiiType.IBAN, text[match.start() : end], normalized, _PRIORITY[PiiType.IBAN])
        )
    return found


def _find_cards(text: str) -> list[_Candidate]:
    found: list[_Candidate] = []
    index = 0
    length = len(text)
    while index < length:
        if not text[index].isdigit() or (index > 0 and text[index - 1].isdigit()):
            index += 1
            continue
        groups: list[str] = []
        spans: list[tuple[int, int]] = []
        cursor = index
        while cursor < length and text[cursor].isdigit():
            start = cursor
            while cursor < length and text[cursor].isdigit():
                cursor += 1
            groups.append(text[start:cursor])
            spans.append((start, cursor))
            separator = cursor
            while separator < length and text[separator] in " -":
                separator += 1
            if separator > cursor and separator < length and text[separator].isdigit():
                cursor = separator
                continue
            break
        if groups and len(groups[0]) <= 2:
            index = spans[1][0] if len(spans) > 1 else max(cursor, index + 1)
            continue
        best_end = 0
        best_digits = ""
        total = 0
        for group_index, group in enumerate(groups):
            if group_index > 0 and len(group) <= 2:
                break
            total += len(group)
            if total > 19:
                break
            if total < 13:
                continue
            digits = "".join(groups[: group_index + 1])
            if _card_digits_valid(digits):
                best_end = spans[group_index][1]
                best_digits = digits
        if best_end:
            raw = text[index:best_end]
            found.append(_Candidate(index, best_end, PiiType.CARD, raw, best_digits, _PRIORITY[PiiType.CARD]))
            index = best_end
        else:
            index = cursor if cursor > index else index + 1
    return found


def _resolve(candidates: list[_Candidate]) -> list[_Candidate]:
    ordered = sorted(candidates, key=lambda item: (-(item.end - item.start), -item.priority, item.start))
    accepted: list[_Candidate] = []
    for candidate in ordered:
        overlapped = any(candidate.start < other.end and other.start < candidate.end for other in accepted)
        if not overlapped:
            accepted.append(candidate)
    accepted.sort(key=lambda item: item.start)
    return accepted


class RedactionSession:
    """Per-request redactor. ``mapping`` is placeholder to the first raw value seen."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.mapping: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._by_value: dict[tuple[str, str], str] = {}

    def redact(self, text: str) -> Redaction:
        if not text:
            return Redaction(text="", findings=[])
        candidates = _resolve(
            [
                *_find_ibans(text),
                *_find_cards(text),
                *_find_emails(text),
                *_find_phones(text),
                *_find_tckn(text),
            ]
        )
        pieces: list[str] = []
        findings: list[Finding] = []
        cursor = 0
        for candidate in candidates:
            placeholder = self._assign(candidate)
            pieces.append(text[cursor : candidate.start])
            pieces.append(placeholder)
            cursor = candidate.end
            finding = Finding(candidate.type.value, placeholder, candidate.start, candidate.end)
            findings.append(finding)
            self.findings.append(finding)
        pieces.append(text[cursor:])
        return Redaction("".join(pieces), findings)

    def counts(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for finding in self.findings:
            totals[finding.type] = totals.get(finding.type, 0) + 1
        return ordered_counts(totals)

    def restore(self, text: str) -> str:
        if not text or not self.mapping or "[" not in text:
            return text
        pattern = re.compile("|".join(re.escape(token) for token in sorted(self.mapping, key=len, reverse=True)))
        return pattern.sub(lambda match: self.mapping[match.group(0)], text)

    def restore_data(self, value: object) -> object:
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_data(item) for item in value]
        if isinstance(value, dict):
            return {key: self.restore_data(item) for key, item in value.items()}
        return value

    def _assign(self, candidate: _Candidate) -> str:
        key = (candidate.type.value, candidate.canonical)
        existing = self._by_value.get(key)
        if existing is not None:
            return existing
        number = self._counters.get(candidate.type.value, 0) + 1
        self._counters[candidate.type.value] = number
        placeholder = f"[{candidate.type.value}_{number}]"
        self._by_value[key] = placeholder
        self.mapping[placeholder] = candidate.raw
        return placeholder


def redact_text(text: str) -> Redaction:
    return RedactionSession().redact(text)
