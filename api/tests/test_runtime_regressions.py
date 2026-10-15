from datetime import datetime
from hashlib import sha256
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient
from src import main
from src.db.session import get_session
from src.middleware import logging as logging_module


@pytest.mark.parametrize(
    ("event", "level"),
    [
        ("device_registered", "info"),
        ("token_invalid", "warning"),
    ],
)
def test_auth_event_logging_uses_safe_structured_fields(monkeypatch, event, level):
    logger = Mock()
    monkeypatch.setattr(logging_module, "logger", logger)
    device_token = "private-device-token"

    logging_module.log_auth_event(
        event,
        device_id=device_token,
        token_hash=sha256(device_token.encode()).hexdigest()[:16],
        error="expired",
    )

    log_method = getattr(logger, level)
    log_method.assert_called_once()
    message, fields = log_method.call_args.args[0], log_method.call_args.kwargs
    assert message == "Authentication event"
    assert fields["auth_event"] == event
    assert fields["device_id_hash"] == sha256(device_token.encode()).hexdigest()[:16]
    assert fields["token_hash"] == sha256(device_token.encode()).hexdigest()[:16]
    assert fields["error"] == "expired"
    assert device_token not in repr(log_method.call_args)


@pytest.mark.parametrize(
    ("query_value", "expected_since"),
    [
        (None, datetime(1970, 1, 1)),
        ("1970-01-01T00:00:00Z", datetime(1970, 1, 1)),
        ("2026-01-01T01:00:00+01:00", datetime(2026, 1, 1)),
        ("2026-01-01T00:00:00", datetime(2026, 1, 1)),
    ],
)
def test_blocklist_delta_normalizes_since_to_naive_utc(monkeypatch, query_value, expected_since):
    result = Mock()
    result.scalars.return_value.all.return_value = []
    session = Mock()
    session.execute = AsyncMock(return_value=result)

    async def override_session():
        yield session

    monkeypatch.setitem(main.app.dependency_overrides, get_session, override_session)
    client = TestClient(main.app)
    try:
        params = {} if query_value is None else {"since": query_value}
        response = client.get("/v1/blocklist/delta", params=params)
    finally:
        client.close()
        main.app.dependency_overrides.pop(get_session, None)

    assert response.status_code == 200
    assert response.json()["additions"] == []
    statement = session.execute.call_args.args[0]
    bound_values = statement.compile().params.values()
    assert expected_since in bound_values
