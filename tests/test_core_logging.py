import json
import logging

import pytest

from naco.core.logging import JsonFormatter, RedactionFilter, redact, setup_logging


@pytest.mark.parametrize("raw,leak", [
    ("login password=hunter2 ok", "hunter2"),
    ("password: 'hunter 2'", "hunter 2"),
    ('{"secret": "s3cr3t"}', "s3cr3t"),
    ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
    ("token=naco_AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
    ("used naco_AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
    ("nas key=sw1-shared-secret", "sw1-shared-secret"),
])
def test_redact(raw, leak):
    assert leak not in redact(raw)


def test_redact_keeps_harmless_text():
    assert redact("user alice accepted on VLAN 10") == "user alice accepted on VLAN 10"


def test_filter_applies_to_child_logger_records(capsys):
    setup_logging("INFO", "text")
    logging.getLogger("naco.tacacs.server").warning("login user=%s password=%s", "bob", "hunter2")
    out = capsys.readouterr().out
    assert "bob" in out
    assert "hunter2" not in out


def test_json_format(capsys):
    setup_logging("INFO", "json")
    logging.getLogger("naco.x").info("hello %s", "world")
    doc = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert doc["msg"] == "hello world"
    assert doc["logger"] == "naco.x"


def test_filter_survives_bad_format_args():
    record = logging.LogRecord("n", logging.INFO, "f", 1, "%d", ("notanint",), None)
    assert RedactionFilter().filter(record)
    assert JsonFormatter().format(record)
