"""PII validators and the redactor. Every fixture is synthetic."""

from __future__ import annotations

import random

import pytest

from aiguard.pii import (
    RedactionSession,
    is_valid_card,
    is_valid_email,
    is_valid_iban,
    is_valid_phone,
    is_valid_tckn,
    redact_text,
)
from tests.support import (
    KNOWN_TCKN,
    NEGATIVE_MOD_TCKN,
    VISA_16,
    generate_tckn,
    generate_tr_iban,
    grouped,
    with_luhn,
)


def test_known_tckn_vectors_and_negative_modulo():
    assert is_valid_tckn(KNOWN_TCKN)
    assert is_valid_tckn(NEGATIVE_MOD_TCKN)
    assert is_valid_tckn("0" + KNOWN_TCKN[1:]) is False
    assert is_valid_tckn(KNOWN_TCKN[:-1] + "0") is False
    assert is_valid_tckn(KNOWN_TCKN + "0") is False


def test_generated_tckns_are_redacted_and_near_misses_stay():
    rng = random.Random(20261120)
    for _ in range(40):
        tckn = generate_tckn(rng)
        assert is_valid_tckn(tckn)
        hidden = redact_text(f"Kayit {tckn} tamam.")
        assert tckn not in hidden.text
        assert hidden.text == "Kayit [TCKN_1] tamam."
        assert hidden.findings[0].type == "TCKN"

        broken = tckn[:-1] + str((int(tckn[-1]) + 1) % 10)
        assert is_valid_tckn(broken) is False
        visible = redact_text(f"Kayit {broken} tamam.")
        assert visible.text == f"Kayit {broken} tamam."
        assert visible.findings == []


def test_plain_eleven_digit_order_numbers_stay():
    kept = 0
    for number in range(48291736500, 48291736650):
        order = f"{number:011d}"
        if is_valid_tckn(order):
            continue
        result = redact_text(f"Order {order} shipped")
        assert result.text == f"Order {order} shipped"
        assert result.findings == []
        kept += 1
    assert kept >= 140


def test_tckn_inside_a_longer_digit_run_stays():
    blob = KNOWN_TCKN + "00"
    result = redact_text(f"Reference {blob}")
    assert blob in result.text
    assert result.findings == []


def test_repeated_tckn_shares_a_placeholder_and_distinct_ones_increment():
    session = RedactionSession()
    first = session.redact(f"A {KNOWN_TCKN}")
    second = session.redact(f"B {KNOWN_TCKN} and {NEGATIVE_MOD_TCKN}")
    assert first.text == "A [TCKN_1]"
    assert second.text == "B [TCKN_1] and [TCKN_2]"
    assert session.mapping["[TCKN_1]"] == KNOWN_TCKN
    assert session.restore(second.text) == f"B {KNOWN_TCKN} and {NEGATIVE_MOD_TCKN}"


@pytest.mark.parametrize(
    "value",
    [
        "GB82WEST12345698765432",
        "GB82 WEST 1234 5698 7654 32",
        "DE89370400440532013000",
        "DE89 3704 0044 0532 0130 00",
        "TR330006100519786457841326",
        "TR33 0006 1005 1978 6457 8413 26",
        "tr330006100519786457841326",
    ],
)
def test_known_ibans_are_valid(value: str):
    assert is_valid_iban(value)


def test_generated_tr_ibans_round_trip_and_bad_checks_stay():
    rng = random.Random(7)
    session = RedactionSession()
    for index in range(15):
        iban = generate_tr_iban(rng)
        assert is_valid_iban(iban)
        spaced = grouped(iban)
        assert is_valid_iban(spaced)
        broken = iban[:-1] + str((int(iban[-1]) + 3) % 10)
        assert is_valid_iban(broken) is False
        result = session.redact(f"IBAN {spaced}.")
        assert iban not in result.text
        assert spaced not in result.text
        assert f"[IBAN_{index + 1}]" in result.text
        assert result.text.endswith(".")
        assert redact_text(f"IBAN {broken}.").text == f"IBAN {broken}."


def test_wrong_length_and_unknown_country_are_not_ibans():
    iban = "TR330006100519786457841326"
    assert is_valid_iban(iban[:-1]) is False
    assert is_valid_iban("US123456789012345678") is False
    assert "TR33" in redact_text("Code TR33 is a prefix, not an account.").text


def test_luhn_cards_with_separators_are_redacted():
    assert with_luhn("411111111111111") == VISA_16
    assert is_valid_card(VISA_16)
    assert is_valid_card(grouped(VISA_16))
    assert is_valid_card(grouped(VISA_16, sep="-"))
    spaced = redact_text(f"Card {grouped(VISA_16)} ok")
    dashed = redact_text(f"Card {grouped(VISA_16, sep='-')} ok")
    assert spaced.text == "Card [CARD_1] ok"
    assert dashed.text == "Card [CARD_1] ok"
    assert spaced.findings[0].start == 5
    assert spaced.findings[0].end == 5 + len(grouped(VISA_16))


def test_invalid_luhn_brandless_and_short_numbers_stay():
    invalid = VISA_16[:-1] + "2"
    assert is_valid_card(invalid) is False
    assert invalid in redact_text(f"Card {invalid}").text
    zeros = "0" * 16
    assert is_valid_card(zeros) is False
    assert zeros in redact_text(f"Batch {zeros}").text
    short = "411111111111"
    assert short in redact_text(f"Short {short}").text
    assert "41111111111111111111" in redact_text("Long 41111111111111111111").text


@pytest.mark.parametrize(
    "payload",
    [
        "411111111111111",
        "422222222222",
        "4" + "0" * 17,
        "510000000000000",
        "222100000000000",
        "272000000000000",
        "34000000000000",
        "37000000000000",
        "601100000000000",
        "650000000000000",
        "644000000000000",
        "979200000000000",
        "3600000000000",
        "3000000000000",
        "352800000000000",
    ],
)
def test_scheme_prefixes_pass_luhn_and_are_redacted(payload: str):
    number = with_luhn(payload)
    assert is_valid_card(number)
    result = redact_text(f"PAN {number}")
    assert result.text == "PAN [CARD_1]"
    assert number not in result.text


def test_expiry_after_a_card_is_left_in_place():
    text = f"Card {grouped(VISA_16)} 12/27"
    result = redact_text(text)
    assert result.text == "Card [CARD_1] 12/27"


def test_same_card_with_different_spacing_shares_a_placeholder():
    session = RedactionSession()
    first = session.redact(VISA_16)
    second = session.redact(grouped(VISA_16, sep="-"))
    assert first.text == "[CARD_1]"
    assert second.text == "[CARD_1]"
    assert session.restore("[CARD_1]") == VISA_16


@pytest.mark.parametrize(
    "phone",
    [
        "+90 532 111 22 33",
        "+905321112233",
        "+90 (532) 111-22-33",
        "0090 532 111 22 33",
        "00 90 532 111 22 33",
        "0532 111 22 33",
        "05321112233",
        "0 532 111 22 33",
        "(0532) 111 22 33",
        "+90 516 111 22 33",
        "0561 111 22 33",
    ],
)
def test_turkish_mobile_formats_are_redacted(phone: str):
    assert is_valid_phone(phone)
    result = redact_text(f"Tel {phone}.")
    assert result.text == "Tel [PHONE_1]."
    assert phone not in result.text


@pytest.mark.parametrize(
    "phone",
    [
        "0212 111 22 33",
        "+90 212 111 22 33",
        "5321112233",
        "+1 202 555 0147",
        "+90 521 111 22 33",
        "0570 111 22 33",
        "12345",
    ],
)
def test_non_mobile_numbers_stay(phone: str):
    assert is_valid_phone(phone) is False
    assert phone in redact_text(f"Call {phone} later").text


def test_national_and_international_forms_share_a_placeholder():
    session = RedactionSession()
    assert session.redact("+90 532 111 22 33").text == "[PHONE_1]"
    assert session.redact("05321112233").text == "[PHONE_1]"


@pytest.mark.parametrize(
    "email",
    [
        "ayse.yilmaz@example.com",
        "Ayse.Yilmaz@Example.COM",
        "user@example.com.tr",
    ],
)
def test_emails_are_redacted(email: str):
    assert is_valid_email(email)
    result = redact_text(f"Write to {email}.")
    assert result.text == "Write to [EMAIL_1]."
    assert email not in result.text


@pytest.mark.parametrize(
    "text",
    [
        "not-an-email",
        "user@localhost",
        "a@b",
        "readme.txt",
        "version 1.2.3",
        "a..b@example.com",
    ],
)
def test_email_lookalikes_stay(text: str):
    assert text in redact_text(f"See {text} please").text


def test_email_case_shares_a_placeholder():
    session = RedactionSession()
    assert session.redact("Ayse.Yilmaz@Example.COM").text == "[EMAIL_1]"
    assert session.redact("ayse.yilmaz@example.com").text == "[EMAIL_1]"


def test_mixed_customer_paragraph_redacts_every_type_in_order():
    text = (
        "Customer 10000000146 paid from TR33 0006 1005 1978 6457 8413 26 "
        "with card 4111 1111 1111 1111, phone +90 532 111 22 33, "
        "email ayse.yilmaz@example.com."
    )
    result = redact_text(text)
    assert result.text == (
        "Customer [TCKN_1] paid from [IBAN_1] "
        "with card [CARD_1], phone [PHONE_1], "
        "email [EMAIL_1]."
    )
    assert [finding.type for finding in result.findings] == ["TCKN", "IBAN", "CARD", "PHONE", "EMAIL"]
    for raw in (
        KNOWN_TCKN,
        "TR33 0006 1005 1978 6457 8413 26",
        "4111 1111 1111 1111",
        "+90 532 111 22 33",
        "ayse.yilmaz@example.com",
    ):
        assert raw not in result.text
        finding = next(item for item in result.findings if text[item.start : item.end] == raw)
        assert text[finding.start : finding.end] == raw


def test_iban_wins_over_a_digit_run_inside_it():
    iban = "TR330006100519786457841326"
    result = redact_text(f"Account {iban}")
    assert result.text == "Account [IBAN_1]"
    assert "CARD" not in {finding.type for finding in result.findings}
    assert "TCKN" not in {finding.type for finding in result.findings}


def test_readme_demo_sentence():
    text = (
        "Customer 10000000146 paid from TR33 0006 1005 1978 6457 8413 26 "
        "with card 4111 1111 1111 1111, phone +90 532 111 22 33, "
        "email ayse.yilmaz@example.com. Order 48291736501 stays."
    )
    assert redact_text(text).text == (
        "Customer [TCKN_1] paid from [IBAN_1] with card [CARD_1], "
        "phone [PHONE_1], email [EMAIL_1]. Order 48291736501 stays."
    )


def test_ordinary_business_prose_is_unchanged():
    text = (
        "Order 48291736501 shipped on 2026-11-20. Total 1,250.00 for room 14. "
        "See the note in readme.txt and call the office at 0212 111 22 33."
    )
    assert is_valid_tckn("48291736501") is False
    assert redact_text(text).text == text


def test_empty_and_turkish_punctuation():
    assert redact_text("").text == ""
    text = f"Müşterinin TCKN'si {KNOWN_TCKN}'dir."
    assert redact_text(text).text == "Müşterinin TCKN'si [TCKN_1]'dir."


def test_restore_replaces_only_known_placeholders():
    session = RedactionSession()
    session.redact(KNOWN_TCKN)
    assert session.restore("id [TCKN_1], unknown [TCKN_9]") == f"id {KNOWN_TCKN}, unknown [TCKN_9]"
    assert session.restore_data({"choices": [{"message": {"content": "See [TCKN_1]"}}]}) == {
        "choices": [{"message": {"content": f"See {KNOWN_TCKN}"}}]
    }
